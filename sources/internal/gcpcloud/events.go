package gcpcloud

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
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

type PayloadValues map[string]any

func ComputeAggregatedRawRecords[T any](items map[string]T, get func(T) []json.RawMessage, scopeField string) []json.RawMessage {
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

type CertificateManagerCertificateRecord struct {
	Name            string                                       `json:"name"`
	Description     string                                       `json:"description"`
	CreateTime      string                                       `json:"createTime"`
	UpdateTime      string                                       `json:"updateTime"`
	Labels          map[string]string                            `json:"labels"`
	SelfManaged     CertificateManagerSelfManagedCertificate     `json:"selfManaged"`
	Managed         CertificateManagerManagedCertificate         `json:"managed"`
	ManagedIdentity CertificateManagerManagedIdentityCertificate `json:"managedIdentity"`
	SanDNSNames     []string                                     `json:"sanDnsnames"`
	PEMCertificate  string                                       `json:"pemCertificate"`
	ExpireTime      string                                       `json:"expireTime"`
	Scope           string                                       `json:"scope"`
	UsedBy          []CertificateManagerUsedBy                   `json:"usedBy"`
	Raw             json.RawMessage                              `json:"-"`
}

type CertificateManagerSelfManagedCertificate struct {
	PEMCertificate string `json:"pemCertificate"`
	PEMPrivateKey  string `json:"pemPrivateKey"`
}

type CertificateManagerManagedCertificate struct {
	Domains                  []string                                     `json:"domains"`
	DNSAuthorizations        []string                                     `json:"dnsAuthorizations"`
	IssuanceConfig           string                                       `json:"issuanceConfig"`
	State                    string                                       `json:"state"`
	ProvisioningIssue        CertificateManagerProvisioningIssue          `json:"provisioningIssue"`
	AuthorizationAttemptInfo []CertificateManagerAuthorizationAttemptInfo `json:"authorizationAttemptInfo"`
}

type CertificateManagerManagedIdentityCertificate struct {
	Identity          string                              `json:"identity"`
	State             string                              `json:"state"`
	ProvisioningIssue CertificateManagerProvisioningIssue `json:"provisioningIssue"`
}

type CertificateManagerProvisioningIssue struct {
	Reason  string `json:"reason"`
	Details string `json:"details"`
}

type CertificateManagerAuthorizationAttemptInfo struct {
	Domain        string `json:"domain"`
	State         string `json:"state"`
	FailureReason string `json:"failureReason"`
	Details       string `json:"details"`
	AttemptTime   string `json:"attemptTime"`
}

type CertificateManagerUsedBy struct {
	Name string `json:"name"`
}

type CertificateManagerCertificateMapRecord struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	CreateTime  string                         `json:"createTime"`
	UpdateTime  string                         `json:"updateTime"`
	Labels      map[string]string              `json:"labels"`
	GCLBTargets []CertificateManagerGCLBTarget `json:"gclbTargets"`
	Raw         json.RawMessage                `json:"-"`
}

type CertificateManagerGCLBTarget struct {
	TargetHTTPSProxy string                       `json:"targetHttpsProxy"`
	TargetSSLProxy   string                       `json:"targetSslProxy"`
	IPConfigs        []CertificateManagerIPConfig `json:"ipConfigs"`
}

type CertificateManagerIPConfig struct {
	IPAddress string `json:"ipAddress"`
	Ports     []int  `json:"ports"`
}

type CertificateManagerCertificateMapEntryRecord struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	CreateTime     string            `json:"createTime"`
	UpdateTime     string            `json:"updateTime"`
	Labels         map[string]string `json:"labels"`
	Hostname       string            `json:"hostname"`
	Matcher        string            `json:"matcher"`
	Certificates   []string          `json:"certificates"`
	State          string            `json:"state"`
	CertificateMap string            `json:"-"`
	Raw            json.RawMessage   `json:"-"`
}

type CertificateManagerDNSAuthorizationRecord struct {
	Name              string                              `json:"name"`
	Description       string                              `json:"description"`
	CreateTime        string                              `json:"createTime"`
	UpdateTime        string                              `json:"updateTime"`
	Labels            map[string]string                   `json:"labels"`
	Domain            string                              `json:"domain"`
	DNSResourceRecord CertificateManagerDNSResourceRecord `json:"dnsResourceRecord"`
	Type              string                              `json:"type"`
	Raw               json.RawMessage                     `json:"-"`
}

type CertificateManagerDNSResourceRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
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

type ComputeInstanceRecord struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Zone              string                    `json:"zone"`
	MachineType       string                    `json:"machineType"`
	Status            string                    `json:"status"`
	Labels            map[string]string         `json:"labels"`
	Tags              ComputeTags               `json:"tags"`
	NetworkInterfaces []ComputeNetworkInterface `json:"networkInterfaces"`
	ServiceAccounts   []ComputeServiceAccount   `json:"serviceAccounts"`
	Disks             []ComputeAttachedDisk     `json:"disks"`
	Raw               json.RawMessage           `json:"-"`
}

type ComputeTags struct {
	Items []string `json:"items"`
}

type ComputeNetworkInterface struct {
	Network       string                `json:"network"`
	Subnetwork    string                `json:"subnetwork"`
	NetworkIP     string                `json:"networkIP"`
	AccessConfigs []ComputeAccessConfig `json:"accessConfigs"`
}

type ComputeAccessConfig struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	NatIP string `json:"natIP"`
}

type ComputeServiceAccount struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

type ComputeAttachedDisk struct {
	Boot              bool                     `json:"boot"`
	AutoDelete        bool                     `json:"autoDelete"`
	Source            string                   `json:"source"`
	DiskEncryptionKey ComputeDiskEncryptionKey `json:"diskEncryptionKey"`
}

type ComputeAddressRecord struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	SelfLink         string            `json:"selfLink"`
	Description      string            `json:"description"`
	Address          string            `json:"address"`
	PrefixLength     int               `json:"prefixLength"`
	Status           string            `json:"status"`
	Region           string            `json:"region"`
	Users            []string          `json:"users"`
	NetworkTier      string            `json:"networkTier"`
	IPVersion        string            `json:"ipVersion"`
	AddressType      string            `json:"addressType"`
	Purpose          string            `json:"purpose"`
	Subnetwork       string            `json:"subnetwork"`
	Network          string            `json:"network"`
	IPv6EndpointType string            `json:"ipv6EndpointType"`
	IPCollection     string            `json:"ipCollection"`
	Labels           map[string]string `json:"labels"`
	Raw              json.RawMessage   `json:"-"`
}

type ComputeBackendBucketRecord struct {
	ID                    string                          `json:"id"`
	Name                  string                          `json:"name"`
	SelfLink              string                          `json:"selfLink"`
	Description           string                          `json:"description"`
	BucketName            string                          `json:"bucketName"`
	EnableCDN             bool                            `json:"enableCdn"`
	CDNPolicy             ComputeBackendBucketCDNPolicy   `json:"cdnPolicy"`
	CustomResponseHeaders []string                        `json:"customResponseHeaders"`
	EdgeSecurityPolicy    string                          `json:"edgeSecurityPolicy"`
	CompressionMode       string                          `json:"compressionMode"`
	LoadBalancingScheme   string                          `json:"loadBalancingScheme"`
	Region                string                          `json:"region"`
	UsedBy                []ComputeBackendBucketReference `json:"usedBy"`
	Raw                   json.RawMessage                 `json:"-"`
}

type ComputeBackendBucketCDNPolicy struct {
	SignedURLKeyNames     []string                                   `json:"signedUrlKeyNames"`
	SignedURLCacheMaxAge  string                                     `json:"signedUrlCacheMaxAgeSec"`
	RequestCoalescing     bool                                       `json:"requestCoalescing"`
	CacheMode             string                                     `json:"cacheMode"`
	DefaultTTL            int                                        `json:"defaultTtl"`
	MaxTTL                int                                        `json:"maxTtl"`
	ClientTTL             int                                        `json:"clientTtl"`
	NegativeCaching       bool                                       `json:"negativeCaching"`
	NegativeCachingPolicy []ComputeBackendBucketNegativeCachingEntry `json:"negativeCachingPolicy"`
	ServeWhileStale       int                                        `json:"serveWhileStale"`
	BypassCacheOnHeaders  []ComputeBackendBucketRequestHeader        `json:"bypassCacheOnRequestHeaders"`
	CacheKeyPolicy        ComputeBackendBucketCacheKeyPolicy         `json:"cacheKeyPolicy"`
}

type ComputeBackendBucketNegativeCachingEntry struct {
	Code int `json:"code"`
	TTL  int `json:"ttl"`
}

type ComputeBackendBucketRequestHeader struct {
	HeaderName string `json:"headerName"`
}

type ComputeBackendBucketCacheKeyPolicy struct {
	QueryStringWhitelist []string `json:"queryStringWhitelist"`
	IncludeHTTPHeaders   []string `json:"includeHttpHeaders"`
}

type ComputeBackendBucketReference struct {
	Reference string `json:"reference"`
}

type ComputeBackendServiceRecord struct {
	ID                   string                                  `json:"id"`
	Name                 string                                  `json:"name"`
	SelfLink             string                                  `json:"selfLink"`
	Description          string                                  `json:"description"`
	Region               string                                  `json:"region"`
	Protocol             string                                  `json:"protocol"`
	PortName             string                                  `json:"portName"`
	LoadBalancingScheme  string                                  `json:"loadBalancingScheme"`
	SessionAffinity      string                                  `json:"sessionAffinity"`
	LocalityLBPolicy     string                                  `json:"localityLbPolicy"`
	TimeoutSec           int                                     `json:"timeoutSec"`
	EnableCDN            bool                                    `json:"enableCDN"`
	HealthChecks         []string                                `json:"healthChecks"`
	Backends             []ComputeBackendServiceBackend          `json:"backends"`
	ConnectionDraining   ComputeBackendServiceConnectionDraining `json:"connectionDraining"`
	LogConfig            ComputeBackendServiceLogConfig          `json:"logConfig"`
	IAP                  ComputeBackendServiceIAP                `json:"iap"`
	SecurityPolicy       string                                  `json:"securityPolicy"`
	Network              string                                  `json:"network"`
	CustomRequestHeaders []string                                `json:"customRequestHeaders"`
	Labels               map[string]string                       `json:"labels"`
	Raw                  json.RawMessage                         `json:"-"`
}

type ComputeBackendServiceBackend struct {
	Group                     string  `json:"group"`
	BalancingMode             string  `json:"balancingMode"`
	CapacityScaler            float64 `json:"capacityScaler"`
	MaxUtilization            float64 `json:"maxUtilization"`
	MaxRatePerInstance        float64 `json:"maxRatePerInstance"`
	MaxConnectionsPerInstance int     `json:"maxConnectionsPerInstance"`
	Failover                  bool    `json:"failover"`
}

type ComputeBackendServiceConnectionDraining struct {
	DrainingTimeoutSec int `json:"drainingTimeoutSec"`
}

type ComputeBackendServiceLogConfig struct {
	Enable     bool    `json:"enable"`
	SampleRate float64 `json:"sampleRate"`
}

type ComputeBackendServiceIAP struct {
	Enabled bool `json:"enabled"`
}

type ComputeNamedPort struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type ComputeInstanceGroupRecord struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	SelfLink    string             `json:"selfLink"`
	Description string             `json:"description"`
	Zone        string             `json:"zone"`
	Region      string             `json:"region"`
	Network     string             `json:"network"`
	Subnetwork  string             `json:"subnetwork"`
	NamedPorts  []ComputeNamedPort `json:"namedPorts"`
	Size        int                `json:"size"`
	Raw         json.RawMessage    `json:"-"`
}

type ComputeInstanceGroupManagerRecord struct {
	ID                  string                           `json:"id"`
	Name                string                           `json:"name"`
	SelfLink            string                           `json:"selfLink"`
	Description         string                           `json:"description"`
	Zone                string                           `json:"zone"`
	Region              string                           `json:"region"`
	BaseInstanceName    string                           `json:"baseInstanceName"`
	InstanceTemplate    string                           `json:"instanceTemplate"`
	TargetSize          int                              `json:"targetSize"`
	TargetPools         []string                         `json:"targetPools"`
	NamedPorts          []ComputeNamedPort               `json:"namedPorts"`
	AutoHealingPolicies []ComputeAutoHealingPolicy       `json:"autoHealingPolicies"`
	CurrentActions      ComputeInstanceGroupActions      `json:"currentActions"`
	Status              ComputeInstanceGroupStatus       `json:"status"`
	UpdatePolicy        ComputeInstanceGroupUpdatePolicy `json:"updatePolicy"`
	DistributionPolicy  ComputeInstanceDistribution      `json:"distributionPolicy"`
	Raw                 json.RawMessage                  `json:"-"`
}

type ComputeAutoHealingPolicy struct {
	HealthCheck     string `json:"healthCheck"`
	InitialDelaySec int    `json:"initialDelaySec"`
}

type ComputeInstanceGroupActions struct {
	None                   int `json:"none"`
	Creating               int `json:"creating"`
	Deleting               int `json:"deleting"`
	Recreating             int `json:"recreating"`
	Refreshing             int `json:"refreshing"`
	Restarting             int `json:"restarting"`
	Verifying              int `json:"verifying"`
	Abandoning             int `json:"abandoning"`
	CreatingWithoutRetries int `json:"creatingWithoutRetries"`
}

type ComputeInstanceGroupStatus struct {
	IsStable      bool `json:"isStable"`
	VersionTarget struct {
		IsReached bool `json:"isReached"`
	} `json:"versionTarget"`
	Stateful struct {
		HasStatefulConfig  bool `json:"hasStatefulConfig"`
		PerInstanceConfigs struct {
			AllEffective bool `json:"allEffective"`
		} `json:"perInstanceConfigs"`
	} `json:"stateful"`
}

type ComputeInstanceGroupUpdatePolicy struct {
	Type                        string `json:"type"`
	MinimalAction               string `json:"minimalAction"`
	MostDisruptiveAllowedAction string `json:"mostDisruptiveAllowedAction"`
	ReplacementMethod           string `json:"replacementMethod"`
	MaxSurge                    string `json:"maxSurge"`
	MaxUnavailable              string `json:"maxUnavailable"`
}

type ComputeInstanceDistribution struct {
	Zones []ComputeInstanceDistributionZone `json:"zones"`
}

type ComputeInstanceDistributionZone struct {
	Zone string `json:"zone"`
}

type ComputeInstanceTemplateRecord struct {
	ID          string                            `json:"id"`
	Name        string                            `json:"name"`
	SelfLink    string                            `json:"selfLink"`
	Description string                            `json:"description"`
	Properties  ComputeInstanceTemplateProperties `json:"properties"`
	Raw         json.RawMessage                   `json:"-"`
}

type ComputeInstanceTemplateProperties struct {
	MachineType            string                    `json:"machineType"`
	Labels                 map[string]string         `json:"labels"`
	Tags                   ComputeTags               `json:"tags"`
	NetworkInterfaces      []ComputeNetworkInterface `json:"networkInterfaces"`
	ServiceAccounts        []ComputeServiceAccount   `json:"serviceAccounts"`
	Disks                  []ComputeAttachedDisk     `json:"disks"`
	ShieldedInstanceConfig ComputeShieldedInstance   `json:"shieldedInstanceConfig"`
}

type ComputeShieldedInstance struct {
	EnableSecureBoot          bool `json:"enableSecureBoot"`
	EnableVtpm                bool `json:"enableVtpm"`
	EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
}

type ComputeNetworkEndpointGroupRecord struct {
	ID                  string                  `json:"id"`
	Name                string                  `json:"name"`
	SelfLink            string                  `json:"selfLink"`
	Description         string                  `json:"description"`
	Zone                string                  `json:"zone"`
	Region              string                  `json:"region"`
	Network             string                  `json:"network"`
	Subnetwork          string                  `json:"subnetwork"`
	NetworkEndpointType string                  `json:"networkEndpointType"`
	DefaultPort         int                     `json:"defaultPort"`
	Size                int                     `json:"size"`
	PscTargetService    string                  `json:"pscTargetService"`
	CloudRun            ComputeNEGCloudRun      `json:"cloudRun"`
	CloudFunction       ComputeNEGCloudFunction `json:"cloudFunction"`
	AppEngine           ComputeNEGAppEngine     `json:"appEngine"`
	Annotations         map[string]string       `json:"annotations"`
	Raw                 json.RawMessage         `json:"-"`
}

type ComputeNEGCloudRun struct {
	Service string `json:"service"`
	Tag     string `json:"tag"`
	URLMask string `json:"urlMask"`
}

type ComputeNEGCloudFunction struct {
	Function string `json:"function"`
	URLMask  string `json:"urlMask"`
}

type ComputeNEGAppEngine struct {
	Service string `json:"service"`
	Version string `json:"version"`
	URLMask string `json:"urlMask"`
}

type ComputeRouterRecord struct {
	ID                          string                 `json:"id"`
	Name                        string                 `json:"name"`
	SelfLink                    string                 `json:"selfLink"`
	Description                 string                 `json:"description"`
	Region                      string                 `json:"region"`
	Network                     string                 `json:"network"`
	NCCGateway                  string                 `json:"nccGateway"`
	Interfaces                  []ComputeRouterIface   `json:"interfaces"`
	BGPPeers                    []ComputeRouterBGPPeer `json:"bgpPeers"`
	BGP                         ComputeRouterBGP       `json:"bgp"`
	NATs                        []ComputeRouterNAT     `json:"nats"`
	EncryptedInterconnectRouter bool                   `json:"encryptedInterconnectRouter"`
	Raw                         json.RawMessage        `json:"-"`
}

type ComputeRouterIface struct {
	Name                         string `json:"name"`
	IPRange                      string `json:"ipRange"`
	PrivateIPAddress             string `json:"privateIpAddress"`
	Subnetwork                   string `json:"subnetwork"`
	LinkedVPNTunnel              string `json:"linkedVpnTunnel"`
	LinkedInterconnectAttachment string `json:"linkedInterconnectAttachment"`
	ManagementType               string `json:"managementType"`
}

type ComputeRouterBGPPeer struct {
	Name                       string `json:"name"`
	InterfaceName              string `json:"interfaceName"`
	IPAddress                  string `json:"ipAddress"`
	PeerIPAddress              string `json:"peerIpAddress"`
	PeerASN                    int64  `json:"peerAsn"`
	AdvertiseMode              string `json:"advertiseMode"`
	AdvertisedRoutePriority    int    `json:"advertisedRoutePriority"`
	Enable                     string `json:"enable"`
	EnableIPv4                 bool   `json:"enableIpv4"`
	EnableIPv6                 bool   `json:"enableIpv6"`
	RouterApplianceInstance    string `json:"routerApplianceInstance"`
	ManagementType             string `json:"managementType"`
	MD5AuthenticationKeyName   string `json:"md5AuthenticationKeyName"`
	CustomLearnedRoutePriority int    `json:"customLearnedRoutePriority"`
}

type ComputeRouterBGP struct {
	ASN               int64    `json:"asn"`
	AdvertiseMode     string   `json:"advertiseMode"`
	AdvertisedGroups  []string `json:"advertisedGroups"`
	KeepaliveInterval int      `json:"keepaliveInterval"`
	IdentifierRange   string   `json:"identifierRange"`
}

type ComputeRouterNAT struct {
	Name                          string                       `json:"name"`
	Type                          string                       `json:"type"`
	NATIPAllocateOption           string                       `json:"natIpAllocateOption"`
	SourceSubnetworkIPRangesToNAT string                       `json:"sourceSubnetworkIpRangesToNat"`
	NATIPs                        []string                     `json:"natIps"`
	DrainNATIPs                   []string                     `json:"drainNatIps"`
	MinPortsPerVM                 int                          `json:"minPortsPerVm"`
	MaxPortsPerVM                 int                          `json:"maxPortsPerVm"`
	EnableDynamicPortAllocation   bool                         `json:"enableDynamicPortAllocation"`
	EnableEndpointIndependentMap  bool                         `json:"enableEndpointIndependentMapping"`
	EndpointTypes                 []string                     `json:"endpointTypes"`
	Subnetworks                   []ComputeRouterNATSubnetwork `json:"subnetworks"`
	LogConfig                     ComputeRouterNATLogConfig    `json:"logConfig"`
	Rules                         []ComputeRouterNATRule       `json:"rules"`
}

type ComputeRouterNATSubnetwork struct {
	Name                  string   `json:"name"`
	SourceIPRangesToNAT   []string `json:"sourceIpRangesToNat"`
	SecondaryIPRangeNames []string `json:"secondaryIpRangeNames"`
}

type ComputeRouterNATLogConfig struct {
	Enable bool   `json:"enable"`
	Filter string `json:"filter"`
}

type ComputeRouterNATRule struct {
	RuleNumber int    `json:"ruleNumber"`
	Match      string `json:"match"`
	Action     struct {
		SourceNATActiveIPs []string `json:"sourceNatActiveIps"`
		SourceNATDrainIPs  []string `json:"sourceNatDrainIps"`
	} `json:"action"`
}

type ComputeVPNGatewayRecord struct {
	ID               string                       `json:"id"`
	Name             string                       `json:"name"`
	SelfLink         string                       `json:"selfLink"`
	Description      string                       `json:"description"`
	Region           string                       `json:"region"`
	Network          string                       `json:"network"`
	GatewayIPVersion string                       `json:"gatewayIpVersion"`
	StackType        string                       `json:"stackType"`
	VPNInterfaces    []ComputeVPNGatewayInterface `json:"vpnInterfaces"`
	Labels           map[string]string            `json:"labels"`
	Raw              json.RawMessage              `json:"-"`
}

type ComputeVPNGatewayInterface struct {
	ID        int    `json:"id"`
	IPAddress string `json:"ipAddress"`
}

type ComputeTargetVPNGatewayRecord struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	SelfLink        string            `json:"selfLink"`
	Description     string            `json:"description"`
	Region          string            `json:"region"`
	Network         string            `json:"network"`
	Status          string            `json:"status"`
	Tunnels         []string          `json:"tunnels"`
	ForwardingRules []string          `json:"forwardingRules"`
	Labels          map[string]string `json:"labels"`
	Raw             json.RawMessage   `json:"-"`
}

type ComputeVPNTunnelRecord struct {
	ID                       string            `json:"id"`
	Name                     string            `json:"name"`
	SelfLink                 string            `json:"selfLink"`
	Description              string            `json:"description"`
	Region                   string            `json:"region"`
	Status                   string            `json:"status"`
	DetailedStatus           string            `json:"detailedStatus"`
	IKEVersion               int               `json:"ikeVersion"`
	PeerIP                   string            `json:"peerIp"`
	PeerExternalGateway      string            `json:"peerExternalGateway"`
	PeerExternalGatewayIface int               `json:"peerExternalGatewayInterface"`
	PeerGCPGateway           string            `json:"peerGcpGateway"`
	TargetVPNGateway         string            `json:"targetVpnGateway"`
	VPNGateway               string            `json:"vpnGateway"`
	VPNGatewayInterface      int               `json:"vpnGatewayInterface"`
	Router                   string            `json:"router"`
	LocalTrafficSelector     []string          `json:"localTrafficSelector"`
	RemoteTrafficSelector    []string          `json:"remoteTrafficSelector"`
	SharedSecretHash         string            `json:"sharedSecretHash"`
	Labels                   map[string]string `json:"labels"`
	Raw                      json.RawMessage   `json:"-"`
}

type ComputeInterconnectAttachmentRecord struct {
	ID                      string            `json:"id"`
	Name                    string            `json:"name"`
	SelfLink                string            `json:"selfLink"`
	Description             string            `json:"description"`
	Region                  string            `json:"region"`
	Router                  string            `json:"router"`
	Interconnect            string            `json:"interconnect"`
	Type                    string            `json:"type"`
	AdminEnabled            bool              `json:"adminEnabled"`
	OperationalStatus       string            `json:"operationalStatus"`
	State                   string            `json:"state"`
	Bandwidth               string            `json:"bandwidth"`
	EdgeAvailabilityDomain  string            `json:"edgeAvailabilityDomain"`
	VlanTag8021q            int               `json:"vlanTag8021q"`
	MTU                     int               `json:"mtu"`
	Encryption              string            `json:"encryption"`
	StackType               string            `json:"stackType"`
	CloudRouterIPAddress    string            `json:"cloudRouterIpAddress"`
	CustomerRouterIPAddress string            `json:"customerRouterIpAddress"`
	IPSecInternalAddresses  []string          `json:"ipsecInternalAddresses"`
	SatisfiesPzs            bool              `json:"satisfiesPzs"`
	Labels                  map[string]string `json:"labels"`
	Raw                     json.RawMessage   `json:"-"`
}

type ComputeExternalVPNGatewayRecord struct {
	ID             string                               `json:"id"`
	Name           string                               `json:"name"`
	SelfLink       string                               `json:"selfLink"`
	Description    string                               `json:"description"`
	RedundancyType string                               `json:"redundancyType"`
	Interfaces     []ComputeExternalVPNGatewayInterface `json:"interfaces"`
	Labels         map[string]string                    `json:"labels"`
	Raw            json.RawMessage                      `json:"-"`
}

type ComputeExternalVPNGatewayInterface struct {
	ID          int    `json:"id"`
	IPAddress   string `json:"ipAddress"`
	IPv6Address string `json:"ipv6Address"`
}

type ComputeInterconnectRecord struct {
	ID                      string                      `json:"id"`
	Name                    string                      `json:"name"`
	SelfLink                string                      `json:"selfLink"`
	Description             string                      `json:"description"`
	Location                string                      `json:"location"`
	RemoteLocation          string                      `json:"remoteLocation"`
	LinkType                string                      `json:"linkType"`
	InterconnectType        string                      `json:"interconnectType"`
	RequestedLinkCount      int                         `json:"requestedLinkCount"`
	ProvisionedLinkCount    int                         `json:"provisionedLinkCount"`
	AdminEnabled            bool                        `json:"adminEnabled"`
	OperationalStatus       string                      `json:"operationalStatus"`
	State                   string                      `json:"state"`
	InterconnectAttachments []string                    `json:"interconnectAttachments"`
	PeerIPAddress           string                      `json:"peerIpAddress"`
	GoogleIPAddress         string                      `json:"googleIpAddress"`
	ExpectedOutages         []ComputeInterconnectOutage `json:"expectedOutages"`
	Labels                  map[string]string           `json:"labels"`
	SatisfiesPzs            bool                        `json:"satisfiesPzs"`
	MACsec                  ComputeInterconnectMACsec   `json:"macsec"`
	MACsecEnabled           bool                        `json:"macsecEnabled"`
	RequestedFeatures       []string                    `json:"requestedFeatures"`
	AvailableFeatures       []string                    `json:"availableFeatures"`
	Raw                     json.RawMessage             `json:"-"`
}

type ComputeInterconnectOutage struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	IssueType        string   `json:"issueType"`
	AffectedCircuits []string `json:"affectedCircuits"`
}

type ComputeInterconnectMACsec struct {
	FailOpen bool `json:"failOpen"`
}

type ComputePacketMirroringRecord struct {
	ID                string                          `json:"id"`
	Name              string                          `json:"name"`
	SelfLink          string                          `json:"selfLink"`
	Description       string                          `json:"description"`
	Region            string                          `json:"region"`
	Network           ComputePacketMirroringReference `json:"network"`
	Priority          int                             `json:"priority"`
	CollectorILB      ComputePacketMirroringCollector `json:"collectorIlb"`
	MirroredResources ComputePacketMirroringResources `json:"mirroredResources"`
	Filter            ComputePacketMirroringFilter    `json:"filter"`
	Enable            string                          `json:"enable"`
	Raw               json.RawMessage                 `json:"-"`
}

type ComputePacketMirroringCollector struct {
	URL          string `json:"url"`
	CanonicalURL string `json:"canonicalUrl"`
}

type ComputePacketMirroringReference struct {
	URL          string `json:"url"`
	CanonicalURL string `json:"canonicalUrl"`
}

type ComputePacketMirroringResources struct {
	Subnetworks []ComputePacketMirroringReference `json:"subnetworks"`
	Instances   []ComputePacketMirroringReference `json:"instances"`
	Tags        []string                          `json:"tags"`
}

type ComputePacketMirroringFilter struct {
	CIDRRanges  []string `json:"cidrRanges"`
	IPProtocols []string `json:"IPProtocols"`
	Direction   string   `json:"direction"`
}

type ComputeNetworkFirewallPolicyRecord struct {
	ID                   string                             `json:"id"`
	Name                 string                             `json:"name"`
	SelfLink             string                             `json:"selfLink"`
	SelfLinkWithID       string                             `json:"selfLinkWithId"`
	Description          string                             `json:"description"`
	Region               string                             `json:"region"`
	Parent               string                             `json:"parent"`
	PolicyType           string                             `json:"policyType"`
	ShortName            string                             `json:"shortName"`
	DisplayName          string                             `json:"displayName"`
	Rules                []ComputeFirewallPolicyRule        `json:"rules"`
	PacketMirroringRules []ComputeFirewallPolicyRule        `json:"packetMirroringRules"`
	Associations         []ComputeFirewallPolicyAssociation `json:"associations"`
	RuleTupleCount       int                                `json:"ruleTupleCount"`
	Raw                  json.RawMessage                    `json:"-"`
}

type ComputeFirewallPolicyRule struct {
	RuleName              string                           `json:"ruleName"`
	Description           string                           `json:"description"`
	Priority              int                              `json:"priority"`
	Action                string                           `json:"action"`
	Direction             string                           `json:"direction"`
	EnableLogging         bool                             `json:"enableLogging"`
	Disabled              bool                             `json:"disabled"`
	TargetResources       []string                         `json:"targetResources"`
	TargetServiceAccounts []string                         `json:"targetServiceAccounts"`
	TargetForwardingRules []string                         `json:"targetForwardingRules"`
	SecurityProfileGroup  string                           `json:"securityProfileGroup"`
	TLSInspect            bool                             `json:"tlsInspect"`
	TargetType            string                           `json:"targetType"`
	Match                 ComputeFirewallPolicyRuleMatcher `json:"match"`
}

type ComputeFirewallPolicyRuleMatcher struct {
	SrcIPRanges     []string                            `json:"srcIpRanges"`
	DestIPRanges    []string                            `json:"destIpRanges"`
	Layer4Configs   []ComputeFirewallPolicyLayer4Config `json:"layer4Configs"`
	SrcSecureTags   []ComputeFirewallPolicySecureTag    `json:"srcSecureTags"`
	SrcNetworks     []string                            `json:"srcNetworks"`
	SrcNetworkType  string                              `json:"srcNetworkType"`
	DestNetworkType string                              `json:"destNetworkType"`
}

type ComputeFirewallPolicyLayer4Config struct {
	IPProtocol string   `json:"ipProtocol"`
	Ports      []string `json:"ports"`
}

type ComputeFirewallPolicySecureTag struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type ComputeFirewallPolicyAssociation struct {
	Name             string `json:"name"`
	AttachmentTarget string `json:"attachmentTarget"`
	FirewallPolicyID string `json:"firewallPolicyId"`
	ShortName        string `json:"shortName"`
	DisplayName      string `json:"displayName"`
}

type ComputeHealthCheckRecord struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name"`
	SelfLink           string                  `json:"selfLink"`
	Description        string                  `json:"description"`
	CheckIntervalSec   int                     `json:"checkIntervalSec"`
	TimeoutSec         int                     `json:"timeoutSec"`
	UnhealthyThreshold int                     `json:"unhealthyThreshold"`
	HealthyThreshold   int                     `json:"healthyThreshold"`
	Type               string                  `json:"type"`
	TCPHealthCheck     ComputeHealthCheckProbe `json:"tcpHealthCheck"`
	SSLHealthCheck     ComputeHealthCheckProbe `json:"sslHealthCheck"`
	HTTPHealthCheck    ComputeHealthCheckProbe `json:"httpHealthCheck"`
	HTTPSHealthCheck   ComputeHealthCheckProbe `json:"httpsHealthCheck"`
	HTTP2HealthCheck   ComputeHealthCheckProbe `json:"http2HealthCheck"`
	GRPCHealthCheck    ComputeHealthCheckProbe `json:"grpcHealthCheck"`
	GRPCTLSHealthCheck ComputeHealthCheckProbe `json:"grpcTlsHealthCheck"`
	SourceRegions      []string                `json:"sourceRegions"`
	Region             string                  `json:"region"`
	LogConfig          ComputeHealthCheckLog   `json:"logConfig"`
	Raw                json.RawMessage         `json:"-"`
}

type ComputeHealthCheckProbe struct {
	Port              int    `json:"port"`
	PortName          string `json:"portName"`
	PortSpecification string `json:"portSpecification"`
	Request           string `json:"request"`
	Response          string `json:"response"`
	ProxyHeader       string `json:"proxyHeader"`
	Host              string `json:"host"`
	RequestPath       string `json:"requestPath"`
	GRPCServiceName   string `json:"grpcServiceName"`
}

type ComputeHealthCheckLog struct {
	Enable bool `json:"enable"`
}

type ComputeSecurityPolicyRecord struct {
	ID                       string                                  `json:"id"`
	Name                     string                                  `json:"name"`
	SelfLink                 string                                  `json:"selfLink"`
	Description              string                                  `json:"description"`
	Region                   string                                  `json:"region"`
	Type                     string                                  `json:"type"`
	Fingerprint              string                                  `json:"fingerprint"`
	Rules                    []ComputeSecurityPolicyRule             `json:"rules"`
	AdaptiveProtectionConfig ComputeSecurityPolicyAdaptiveProtection `json:"adaptiveProtectionConfig"`
	AdvancedOptionsConfig    ComputeSecurityPolicyAdvancedOptions    `json:"advancedOptionsConfig"`
	Associations             []ComputeSecurityPolicyAssociation      `json:"associations"`
	Labels                   map[string]string                       `json:"labels"`
	Raw                      json.RawMessage                         `json:"-"`
}

type ComputeSecurityPolicyRule struct {
	Priority    int                        `json:"priority"`
	Description string                     `json:"description"`
	Action      string                     `json:"action"`
	Preview     bool                       `json:"preview"`
	Match       ComputeSecurityPolicyMatch `json:"match"`
}

type ComputeSecurityPolicyMatch struct {
	VersionedExpr string                           `json:"versionedExpr"`
	Config        ComputeSecurityPolicyMatchConfig `json:"config"`
	Expr          ComputeSecurityPolicyExpr        `json:"expr"`
}

type ComputeSecurityPolicyMatchConfig struct {
	SrcIPRanges []string `json:"srcIpRanges"`
}

type ComputeSecurityPolicyExpr struct {
	Expression string `json:"expression"`
}

type ComputeSecurityPolicyAdaptiveProtection struct {
	Layer7DDoSDefenseConfig ComputeSecurityPolicyLayer7DDoSDefense `json:"layer7DdosDefenseConfig"`
}

type ComputeSecurityPolicyLayer7DDoSDefense struct {
	Enable bool `json:"enable"`
}

type ComputeSecurityPolicyAdvancedOptions struct {
	JSONParsing          string   `json:"jsonParsing"`
	LogLevel             string   `json:"logLevel"`
	UserIPRequestHeaders []string `json:"userIpRequestHeaders"`
}

type ComputeSecurityPolicyAssociation struct {
	Name             string   `json:"name"`
	AttachmentID     string   `json:"attachmentId"`
	ExcludedProjects []string `json:"excludedProjects"`
	ExcludedFolders  []string `json:"excludedFolders"`
	SecurityPolicyID string   `json:"securityPolicyId"`
	ShortName        string   `json:"shortName"`
}

type ComputeURLMapRecord struct {
	ID                 string                     `json:"id"`
	Name               string                     `json:"name"`
	SelfLink           string                     `json:"selfLink"`
	Description        string                     `json:"description"`
	Region             string                     `json:"region"`
	DefaultService     string                     `json:"defaultService"`
	DefaultRouteAction ComputeURLMapRouteAction   `json:"defaultRouteAction"`
	DefaultURLRedirect ComputeURLMapURLRedirect   `json:"defaultUrlRedirect"`
	HostRules          []ComputeURLMapHostRule    `json:"hostRules"`
	PathMatchers       []ComputeURLMapPathMatcher `json:"pathMatchers"`
	Tests              []ComputeURLMapTest        `json:"tests"`
	Fingerprint        string                     `json:"fingerprint"`
	Raw                json.RawMessage            `json:"-"`
}

type ComputeURLMapHostRule struct {
	Description string   `json:"description"`
	Hosts       []string `json:"hosts"`
	PathMatcher string   `json:"pathMatcher"`
}

type ComputeURLMapPathMatcher struct {
	Name               string                   `json:"name"`
	Description        string                   `json:"description"`
	DefaultService     string                   `json:"defaultService"`
	DefaultRouteAction ComputeURLMapRouteAction `json:"defaultRouteAction"`
	DefaultURLRedirect ComputeURLMapURLRedirect `json:"defaultUrlRedirect"`
	PathRules          []ComputeURLMapPathRule  `json:"pathRules"`
	RouteRules         []ComputeURLMapRouteRule `json:"routeRules"`
}

type ComputeURLMapPathRule struct {
	Paths       []string                 `json:"paths"`
	Service     string                   `json:"service"`
	RouteAction ComputeURLMapRouteAction `json:"routeAction"`
	URLRedirect ComputeURLMapURLRedirect `json:"urlRedirect"`
}

type ComputeURLMapRouteRule struct {
	Priority    int                      `json:"priority"`
	Service     string                   `json:"service"`
	RouteAction ComputeURLMapRouteAction `json:"routeAction"`
	URLRedirect ComputeURLMapURLRedirect `json:"urlRedirect"`
}

type ComputeURLMapRouteAction struct {
	WeightedBackendServices []ComputeURLMapWeightedBackendService `json:"weightedBackendServices"`
}

type ComputeURLMapWeightedBackendService struct {
	BackendService string `json:"backendService"`
	Weight         int    `json:"weight"`
}

type ComputeURLMapURLRedirect struct {
	HostRedirect         string `json:"hostRedirect"`
	PathRedirect         string `json:"pathRedirect"`
	PrefixRedirect       string `json:"prefixRedirect"`
	RedirectResponseCode string `json:"redirectResponseCode"`
	HTTPSRedirect        bool   `json:"httpsRedirect"`
	StripQuery           bool   `json:"stripQuery"`
}

type ComputeURLMapTest struct {
	Description string `json:"description"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Service     string `json:"service"`
}

type ComputeTargetHTTPProxyRecord struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	SelfLink                string          `json:"selfLink"`
	Description             string          `json:"description"`
	URLMap                  string          `json:"urlMap"`
	Region                  string          `json:"region"`
	ProxyBind               bool            `json:"proxyBind"`
	Fingerprint             string          `json:"fingerprint"`
	HTTPKeepAliveTimeoutSec int             `json:"httpKeepAliveTimeoutSec"`
	Raw                     json.RawMessage `json:"-"`
}

type ComputeTargetHTTPSProxyRecord struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	SelfLink                string          `json:"selfLink"`
	Description             string          `json:"description"`
	URLMap                  string          `json:"urlMap"`
	SSLCertificates         []string        `json:"sslCertificates"`
	CertificateMap          string          `json:"certificateMap"`
	QUICOverride            string          `json:"quicOverride"`
	SSLPolicy               string          `json:"sslPolicy"`
	Region                  string          `json:"region"`
	ProxyBind               bool            `json:"proxyBind"`
	ServerTLSPolicy         string          `json:"serverTlsPolicy"`
	AuthorizationPolicy     string          `json:"authorizationPolicy"`
	Fingerprint             string          `json:"fingerprint"`
	HTTPKeepAliveTimeoutSec int             `json:"httpKeepAliveTimeoutSec"`
	Raw                     json.RawMessage `json:"-"`
}

type ComputeTargetSSLProxyRecord struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	SelfLink        string          `json:"selfLink"`
	Description     string          `json:"description"`
	Service         string          `json:"service"`
	SSLCertificates []string        `json:"sslCertificates"`
	CertificateMap  string          `json:"certificateMap"`
	SSLPolicy       string          `json:"sslPolicy"`
	ProxyHeader     string          `json:"proxyHeader"`
	Raw             json.RawMessage `json:"-"`
}

type ComputeTargetTCPProxyRecord struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	SelfLink            string          `json:"selfLink"`
	Description         string          `json:"description"`
	Service             string          `json:"service"`
	ProxyHeader         string          `json:"proxyHeader"`
	ProxyBind           bool            `json:"proxyBind"`
	LoadBalancingScheme string          `json:"loadBalancingScheme"`
	Region              string          `json:"region"`
	Raw                 json.RawMessage `json:"-"`
}

type ComputeTargetGRPCProxyRecord struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	SelfLink             string          `json:"selfLink"`
	Description          string          `json:"description"`
	URLMap               string          `json:"urlMap"`
	ValidateForProxyless bool            `json:"validateForProxyless"`
	Fingerprint          string          `json:"fingerprint"`
	Raw                  json.RawMessage `json:"-"`
}

type ComputeSSLPolicyRecord struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	SelfLink               string          `json:"selfLink"`
	Description            string          `json:"description"`
	Profile                string          `json:"profile"`
	MinTLSVersion          string          `json:"minTlsVersion"`
	EnabledFeatures        []string        `json:"enabledFeatures"`
	CustomFeatures         []string        `json:"customFeatures"`
	PostQuantumKeyExchange string          `json:"postQuantumKeyExchange"`
	Fingerprint            string          `json:"fingerprint"`
	Region                 string          `json:"region"`
	Raw                    json.RawMessage `json:"-"`
}

type ComputeSSLCertificateRecord struct {
	ID                      string                           `json:"id"`
	Name                    string                           `json:"name"`
	SelfLink                string                           `json:"selfLink"`
	Description             string                           `json:"description"`
	Managed                 ComputeSSLCertificateManaged     `json:"managed"`
	SelfManaged             ComputeSSLCertificateSelfManaged `json:"selfManaged"`
	Type                    string                           `json:"type"`
	SubjectAlternativeNames []string                         `json:"subjectAlternativeNames"`
	ExpireTime              string                           `json:"expireTime"`
	Region                  string                           `json:"region"`
	Raw                     json.RawMessage                  `json:"-"`
}

type ComputeSSLCertificateManaged struct {
	Domains      []string          `json:"domains"`
	Status       string            `json:"status"`
	DomainStatus map[string]string `json:"domainStatus"`
}

type ComputeSSLCertificateSelfManaged struct {
	Certificate string `json:"certificate"`
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

type ComputeFirewallRecord struct {
	ID                    string                   `json:"id"`
	Name                  string                   `json:"name"`
	Network               string                   `json:"network"`
	Direction             string                   `json:"direction"`
	Disabled              bool                     `json:"disabled"`
	SourceRanges          []string                 `json:"sourceRanges"`
	Allowed               []ComputeFirewallAllowed `json:"allowed"`
	TargetTags            []string                 `json:"targetTags"`
	TargetServiceAccounts []string                 `json:"targetServiceAccounts"`
	Raw                   json.RawMessage          `json:"-"`
}

type ComputeFirewallAllowed struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

type ComputeRouteRecord struct {
	ID                            string          `json:"id"`
	Name                          string          `json:"name"`
	SelfLink                      string          `json:"selfLink"`
	Description                   string          `json:"description"`
	Network                       string          `json:"network"`
	DestRange                     string          `json:"destRange"`
	Priority                      int             `json:"priority"`
	Tags                          []string        `json:"tags"`
	NextHopGateway                string          `json:"nextHopGateway"`
	NextHopInstance               string          `json:"nextHopInstance"`
	NextHopIP                     string          `json:"nextHopIp"`
	NextHopVPNGateway             string          `json:"nextHopVpnGateway"`
	NextHopVPNTunnel              string          `json:"nextHopVpnTunnel"`
	NextHopILB                    string          `json:"nextHopIlb"`
	NextHopNetwork                string          `json:"nextHopNetwork"`
	NextHopPeering                string          `json:"nextHopPeering"`
	NextHopHub                    string          `json:"nextHopHub"`
	NextHopInterconnectAttachment string          `json:"nextHopInterconnectAttachment"`
	RouteType                     string          `json:"routeType"`
	RouteStatus                   string          `json:"routeStatus"`
	NextHopOrigin                 string          `json:"nextHopOrigin"`
	NextHopMed                    int             `json:"nextHopMed"`
	CreationTimestamp             string          `json:"creationTimestamp"`
	Raw                           json.RawMessage `json:"-"`
}

type ComputeForwardingRuleRecord struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	SelfLink            string            `json:"selfLink"`
	Description         string            `json:"description"`
	Region              string            `json:"region"`
	IPAddress           string            `json:"IPAddress"`
	IPProtocol          string            `json:"IPProtocol"`
	IPVersion           string            `json:"ipVersion"`
	LoadBalancingScheme string            `json:"loadBalancingScheme"`
	PortRange           string            `json:"portRange"`
	Ports               []string          `json:"ports"`
	AllPorts            bool              `json:"allPorts"`
	AllowGlobalAccess   bool              `json:"allowGlobalAccess"`
	Network             string            `json:"network"`
	Subnetwork          string            `json:"subnetwork"`
	NetworkTier         string            `json:"networkTier"`
	Target              string            `json:"target"`
	BackendService      string            `json:"backendService"`
	ServiceLabel        string            `json:"serviceLabel"`
	ServiceName         string            `json:"serviceName"`
	Labels              map[string]string `json:"labels"`
	Raw                 json.RawMessage   `json:"-"`
}

type ComputeSubnetworkRecord struct {
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
	Raw                   json.RawMessage   `json:"-"`
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

type VPCAccessConnectorRecord struct {
	Name              string                   `json:"name"`
	Network           string                   `json:"network"`
	IPCIDRRange       string                   `json:"ipCidrRange"`
	State             string                   `json:"state"`
	MinThroughput     int                      `json:"minThroughput"`
	MaxThroughput     int                      `json:"maxThroughput"`
	ConnectedProjects []string                 `json:"connectedProjects"`
	Subnet            VPCAccessConnectorSubnet `json:"subnet"`
	MachineType       string                   `json:"machineType"`
	MinInstances      int                      `json:"minInstances"`
	MaxInstances      int                      `json:"maxInstances"`
	Raw               json.RawMessage          `json:"-"`
}

type VPCAccessConnectorSubnet struct {
	Name      string `json:"name"`
	ProjectID string `json:"projectId"`
}

func (record ComputeAddressRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name, record.Address)
}

func (record ComputeBackendBucketRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name, record.BucketName)
}

func (record ComputeBackendServiceRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceGroupRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceGroupManagerRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInstanceTemplateRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkEndpointGroupRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeRouterRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeVPNTunnelRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInterconnectAttachmentRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeExternalVPNGatewayRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeInterconnectRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputePacketMirroringRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkFirewallPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.SelfLinkWithID, record.ID, record.Name)
}

func (record ComputeDiskRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeForwardingRuleRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeHealthCheckRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeNetworkRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeRouteRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSecurityPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSSLCertificateRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSubnetworkRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetHTTPProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetHTTPSProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetSSLProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetTCPProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeTargetGRPCProxyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeSSLPolicyRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record ComputeURLMapRecord) CerebroResourceID() string {
	return firstNonEmpty(record.SelfLink, record.ID, record.Name)
}

func (record CertificateManagerCertificateRecord) CerebroResourceID() string {
	return record.Name
}

func (record BigtableInstanceRecord) CerebroResourceID() string {
	return record.Name
}

func (record BigtableTableRecord) CerebroResourceID() string {
	return record.Name
}

func (record CertificateManagerCertificateMapRecord) CerebroResourceID() string {
	return record.Name
}

func (record CertificateManagerCertificateMapEntryRecord) CerebroResourceID() string {
	return record.Name
}

func (record CertificateManagerDNSAuthorizationRecord) CerebroResourceID() string {
	return record.Name
}

func (record VPCAccessConnectorRecord) CerebroResourceID() string {
	return record.Name
}

func (record MonitoringAlertPolicyRecord) CerebroResourceID() string {
	return record.Name
}

func (record MonitoringNotificationChannelRecord) CerebroResourceID() string {
	return record.Name
}

func (record SpannerInstanceRecord) CerebroResourceID() string {
	return record.Name
}

func (record SpannerDatabaseRecord) CerebroResourceID() string {
	return record.Name
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

type MonitoringAlertPolicyRecord struct {
	Name                 string                           `json:"name"`
	DisplayName          string                           `json:"displayName"`
	Documentation        MonitoringDocumentation          `json:"documentation"`
	UserLabels           map[string]string                `json:"userLabels"`
	Enabled              *bool                            `json:"enabled"`
	Combiner             string                           `json:"combiner"`
	Conditions           []MonitoringAlertPolicyCondition `json:"conditions"`
	NotificationChannels []string                         `json:"notificationChannels"`
	Severity             string                           `json:"severity"`
	CreationRecord       MonitoringMutationRecord         `json:"creationRecord"`
	MutationRecord       MonitoringMutationRecord         `json:"mutationRecord"`
	Raw                  json.RawMessage                  `json:"-"`
}

type MonitoringDocumentation struct {
	Content  string `json:"content"`
	MimeType string `json:"mimeType"`
	Subject  string `json:"subject"`
}

type MonitoringMutationRecord struct {
	MutateTime string `json:"mutateTime"`
	MutatedBy  string `json:"mutatedBy"`
}

type MonitoringAlertPolicyCondition struct {
	Name                             string          `json:"name"`
	DisplayName                      string          `json:"displayName"`
	ConditionThreshold               json.RawMessage `json:"conditionThreshold"`
	ConditionAbsent                  json.RawMessage `json:"conditionAbsent"`
	ConditionMonitoringQueryLanguage json.RawMessage `json:"conditionMonitoringQueryLanguage"`
	ConditionPrometheusQueryLanguage json.RawMessage `json:"conditionPrometheusQueryLanguage"`
	ConditionMatchedLog              json.RawMessage `json:"conditionMatchedLog"`
	ConditionSQL                     json.RawMessage `json:"conditionSql"`
}

type MonitoringNotificationChannelRecord struct {
	Name               string                   `json:"name"`
	Type               string                   `json:"type"`
	DisplayName        string                   `json:"displayName"`
	Description        string                   `json:"description"`
	Labels             map[string]string        `json:"labels"`
	UserLabels         map[string]string        `json:"userLabels"`
	Enabled            *bool                    `json:"enabled"`
	VerificationStatus string                   `json:"verificationStatus"`
	SensitiveLabels    json.RawMessage          `json:"sensitiveLabels"`
	CreationRecord     MonitoringMutationRecord `json:"creationRecord"`
	MutationRecord     MonitoringMutationRecord `json:"mutationRecord"`
	Raw                json.RawMessage          `json:"-"`
}

type LoggingMetricRecord struct {
	Name             string                  `json:"name"`
	Description      string                  `json:"description"`
	Filter           string                  `json:"filter"`
	Disabled         bool                    `json:"disabled"`
	MetricDescriptor LoggingMetricDescriptor `json:"metricDescriptor"`
	ValueExtractor   string                  `json:"valueExtractor"`
	LabelExtractors  map[string]string       `json:"labelExtractors"`
	BucketOptions    json.RawMessage         `json:"bucketOptions"`
	CreateTime       string                  `json:"createTime"`
	UpdateTime       string                  `json:"updateTime"`
	Version          string                  `json:"version"`
	Raw              json.RawMessage         `json:"-"`
}

type LoggingMetricDescriptor struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	MetricKind  string `json:"metricKind"`
	ValueType   string `json:"valueType"`
	Unit        string `json:"unit"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
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

type BigtableInstanceRecord struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"displayName"`
	State        string            `json:"state"`
	Type         string            `json:"type"`
	Labels       map[string]string `json:"labels"`
	CreateTime   string            `json:"createTime"`
	SatisfiesPZS bool              `json:"satisfiesPzs"`
	Raw          json.RawMessage   `json:"-"`
}

type BigtableTableRecord struct {
	Name                  string                     `json:"name"`
	InstanceName          string                     `json:"-"`
	ClusterStates         map[string]json.RawMessage `json:"clusterStates"`
	ColumnFamilies        map[string]json.RawMessage `json:"columnFamilies"`
	Granularity           string                     `json:"granularity"`
	RestoreInfo           json.RawMessage            `json:"restoreInfo"`
	DeletionProtection    bool                       `json:"deletionProtection"`
	ChangeStreamConfig    BigtableChangeStreamConfig `json:"changeStreamConfig"`
	AutomatedBackupPolicy json.RawMessage            `json:"automatedBackupPolicy"`
	Raw                   json.RawMessage            `json:"-"`
}

type BigtableChangeStreamConfig struct {
	RetentionPeriod string `json:"retentionPeriod"`
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

type SpannerInstanceRecord struct {
	Name                 string            `json:"name"`
	Config               string            `json:"config"`
	DisplayName          string            `json:"displayName"`
	NodeCount            int               `json:"nodeCount"`
	ProcessingUnits      int               `json:"processingUnits"`
	State                string            `json:"state"`
	Labels               map[string]string `json:"labels"`
	EndpointURIs         []string          `json:"endpointUris"`
	CreateTime           string            `json:"createTime"`
	UpdateTime           string            `json:"updateTime"`
	InstanceType         string            `json:"instanceType"`
	AutoscalingConfig    json.RawMessage   `json:"autoscalingConfig"`
	FreeInstanceMetadata json.RawMessage   `json:"freeInstanceMetadata"`
	Raw                  json.RawMessage   `json:"-"`
}

type SpannerDatabaseRecord struct {
	Name                   string                  `json:"name"`
	InstanceName           string                  `json:"-"`
	State                  string                  `json:"state"`
	CreateTime             string                  `json:"createTime"`
	RestoreInfo            json.RawMessage         `json:"restoreInfo"`
	VersionRetentionPeriod string                  `json:"versionRetentionPeriod"`
	EarliestVersionTime    string                  `json:"earliestVersionTime"`
	EncryptionConfig       SpannerEncryptionConfig `json:"encryptionConfig"`
	EncryptionInfo         []SpannerEncryptionInfo `json:"encryptionInfo"`
	DatabaseDialect        string                  `json:"databaseDialect"`
	EnableDropProtection   bool                    `json:"enableDropProtection"`
	Reconciling            bool                    `json:"reconciling"`
	Raw                    json.RawMessage         `json:"-"`
}

type SpannerEncryptionConfig struct {
	EncryptionType string `json:"encryptionType"`
	KMSKeyName     string `json:"kmsKeyName"`
}

type SpannerEncryptionInfo struct {
	EncryptionType string `json:"encryptionType"`
	KMSKeyVersion  string `json:"kmsKeyVersion"`
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

func CertificateManagerCertificateEvent(settings Settings, record CertificateManagerCertificateRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	certificateType := certificateManagerCertificateType(record)
	usedBy := certificateManagerUsedByNames(record.UsedBy)
	attemptDomains, attemptStates, attemptFailures := certificateManagerAuthorizationAttemptSummary(record.Managed.AuthorizationAttemptInfo)
	attributes := cloudResourceAttributes(settings, "certificate_manager_certificate", record.Name, lastPathSegment(record.Name), "certificate_manager_certificate", location, record.Labels)
	attributes["description"] = record.Description
	attributes["certificate_type"] = certificateType
	attributes["type"] = certificateType
	attributes["managed"] = boolString(certificateType == "MANAGED")
	attributes["self_managed"] = boolString(certificateType == "SELF_MANAGED")
	attributes["managed_identity"] = boolString(certificateType == "MANAGED_IDENTITY")
	attributes["managed_state"] = firstNonEmpty(record.Managed.State, record.ManagedIdentity.State)
	attributes["managed_identity_id"] = record.ManagedIdentity.Identity
	attributes["managed_identity_state"] = record.ManagedIdentity.State
	attributes["managed_identity_provisioning_issue_reason"] = record.ManagedIdentity.ProvisioningIssue.Reason
	attributes["managed_domains"] = strings.Join(record.Managed.Domains, ",")
	attributes["managed_domains_count"] = strconv.Itoa(len(record.Managed.Domains))
	attributes["dns_authorizations"] = strings.Join(lastPathSegments(record.Managed.DNSAuthorizations), ",")
	attributes["dns_authorization_urls"] = strings.Join(record.Managed.DNSAuthorizations, ",")
	attributes["dns_authorizations_count"] = strconv.Itoa(len(record.Managed.DNSAuthorizations))
	attributes["issuance_config"] = lastPathSegment(record.Managed.IssuanceConfig)
	attributes["issuance_config_url"] = record.Managed.IssuanceConfig
	attributes["provisioning_issue_reason"] = record.Managed.ProvisioningIssue.Reason
	attributes["authorization_attempt_domains"] = strings.Join(attemptDomains, ",")
	attributes["authorization_attempt_states"] = strings.Join(attemptStates, ",")
	attributes["authorization_failure_reasons"] = strings.Join(attemptFailures, ",")
	attributes["san_dns_names"] = strings.Join(record.SanDNSNames, ",")
	attributes["sans"] = strings.Join(record.SanDNSNames, ",")
	attributes["san_count"] = strconv.Itoa(len(record.SanDNSNames))
	attributes["scope"] = record.Scope
	attributes["expire_time"] = record.ExpireTime
	attributes["used_by"] = strings.Join(lastPathSegments(usedBy), ",")
	attributes["used_by_urls"] = strings.Join(usedBy, ",")
	attributes["used_by_count"] = strconv.Itoa(len(usedBy))
	attributes["tls_enabled"] = "true"
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-certificate-manager-certificate-"+record.Name, "gcp.certificate_manager_certificate", "gcp/certificate_manager_certificate/v1", payload, attributes)
}

func CertificateManagerCertificateMapEvent(settings Settings, record CertificateManagerCertificateMapRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	httpsProxies, sslProxies, ipAddresses, ports := certificateManagerGCLBTargets(record.GCLBTargets)
	attributes := cloudResourceAttributes(settings, "certificate_manager_certificate_map", record.Name, lastPathSegment(record.Name), "certificate_manager_certificate_map", location, record.Labels)
	attributes["description"] = record.Description
	attributes["target_https_proxies"] = strings.Join(lastPathSegments(httpsProxies), ",")
	attributes["target_https_proxy_urls"] = strings.Join(httpsProxies, ",")
	attributes["target_ssl_proxies"] = strings.Join(lastPathSegments(sslProxies), ",")
	attributes["target_ssl_proxy_urls"] = strings.Join(sslProxies, ",")
	attributes["gclb_targets_count"] = strconv.Itoa(len(record.GCLBTargets))
	attributes["ip_addresses"] = strings.Join(ipAddresses, ",")
	attributes["ports"] = strings.Join(ports, ",")
	attributes["internet_exposed"] = boolString(len(ipAddresses) != 0)
	attributes["public"] = boolString(len(ipAddresses) != 0)
	attributes["tls_enabled"] = "true"
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-certificate-manager-certificate-map-"+record.Name, "gcp.certificate_manager_certificate_map", "gcp/certificate_manager_certificate_map/v1", payload, attributes)
}

func CertificateManagerCertificateMapEntryEvent(settings Settings, record CertificateManagerCertificateMapEntryRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	certificates := lastPathSegments(record.Certificates)
	attributes := cloudResourceAttributes(settings, "certificate_manager_certificate_map_entry", record.Name, lastPathSegment(record.Name), "certificate_manager_certificate_map_entry", location, record.Labels)
	attributes["description"] = record.Description
	attributes["certificate_map"] = lastPathSegment(record.CertificateMap)
	attributes["certificate_map_url"] = record.CertificateMap
	attributes["hostname"] = record.Hostname
	attributes["matcher"] = record.Matcher
	attributes["primary"] = boolString(strings.EqualFold(record.Matcher, "PRIMARY"))
	attributes["state"] = record.State
	attributes["serving"] = boolString(strings.EqualFold(record.State, "ACTIVE"))
	attributes["certificates"] = strings.Join(certificates, ",")
	attributes["certificate_urls"] = strings.Join(record.Certificates, ",")
	attributes["certificates_count"] = strconv.Itoa(len(record.Certificates))
	attributes["tls_enabled"] = boolString(len(record.Certificates) != 0)
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"certificate_map": record.CertificateMap, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-certificate-manager-certificate-map-entry-"+record.Name, "gcp.certificate_manager_certificate_map_entry", "gcp/certificate_manager_certificate_map_entry/v1", payload, attributes)
}

func CertificateManagerDNSAuthorizationEvent(settings Settings, record CertificateManagerDNSAuthorizationRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "certificate_manager_dns_authorization", record.Name, lastPathSegment(record.Name), "certificate_manager_dns_authorization", location, record.Labels)
	attributes["description"] = record.Description
	attributes["domain_name"] = record.Domain
	attributes["authorization_type"] = record.Type
	attributes["dns_record_name"] = record.DNSResourceRecord.Name
	attributes["dns_record_type"] = record.DNSResourceRecord.Type
	attributes["dns_record_data"] = record.DNSResourceRecord.Data
	attributes["dns_challenge_configured"] = boolString(record.DNSResourceRecord.Name != "" && record.DNSResourceRecord.Data != "")
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-certificate-manager-dns-authorization-"+record.Name, "gcp.certificate_manager_dns_authorization", "gcp/certificate_manager_dns_authorization/v1", payload, attributes)
}

func VPCAccessConnectorEvent(settings Settings, record VPCAccessConnectorRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "vpc_access_connector", record.Name, lastPathSegment(record.Name), "vpc_access_connector", location, nil)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ip_cidr_range"] = record.IPCIDRRange
	attributes["state"] = record.State
	attributes["ready"] = boolString(strings.EqualFold(record.State, "READY"))
	attributes["machine_type"] = record.MachineType
	attributes["min_instances"] = strconv.Itoa(record.MinInstances)
	attributes["max_instances"] = strconv.Itoa(record.MaxInstances)
	attributes["min_throughput_mbps"] = strconv.Itoa(record.MinThroughput)
	attributes["max_throughput_mbps"] = strconv.Itoa(record.MaxThroughput)
	attributes["connected_projects"] = strings.Join(record.ConnectedProjects, ",")
	attributes["connected_projects_count"] = strconv.Itoa(len(record.ConnectedProjects))
	attributes["subnet"] = record.Subnet.Name
	attributes["subnet_project_id"] = record.Subnet.ProjectID
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-vpc-access-connector-"+record.Name, "gcp.vpc_access_connector", "gcp/vpc_access_connector/v1", payload, attributes)
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

func ComputeInstanceEvent(settings Settings, record ComputeInstanceRecord) (*primitives.Event, error) {
	location := lastPathSegment(record.Zone)
	network := firstComputeNetworkInterface(record)
	publicIP := computePublicIP(record)
	serviceAccountEmail := firstComputeServiceAccountEmail(record)
	attributes := cloudResourceAttributes(settings, "compute_instance", firstNonEmpty(record.ID, record.Name), record.Name, "compute_instance", location, record.Labels)
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
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_instance", "gcp/compute_instance/v1", payload, attributes)
}

func ComputeAddressEvent(settings Settings, record ComputeAddressRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name, record.Address)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeAddressExternal(record.AddressType)
	inUse := strings.EqualFold(record.Status, "IN_USE")
	usedBy := lastPathSegments(record.Users)
	attributes := cloudResourceAttributes(settings, "compute_address", resourceID, record.Name, "compute_address", location, record.Labels)
	attributes["description"] = record.Description
	attributes["ip_address"] = record.Address
	attributes["address"] = record.Address
	if record.PrefixLength > 0 {
		attributes["prefix_length"] = strconv.Itoa(record.PrefixLength)
	}
	attributes["status"] = record.Status
	attributes["reserved"] = boolString(strings.EqualFold(record.Status, "RESERVED"))
	attributes["in_use"] = boolString(inUse)
	attributes["network_tier"] = record.NetworkTier
	attributes["ip_version"] = record.IPVersion
	attributes["address_type"] = record.AddressType
	attributes["type"] = record.AddressType
	attributes["purpose"] = record.Purpose
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["users"] = strings.Join(usedBy, ",")
	attributes["user_urls"] = strings.Join(record.Users, ",")
	attributes["used_by"] = strings.Join(usedBy, ",")
	attributes["used_by_urls"] = strings.Join(record.Users, ",")
	attributes["users_count"] = strconv.Itoa(len(record.Users))
	attributes["ipv6_endpoint_type"] = record.IPv6EndpointType
	attributes["ip_collection"] = record.IPCollection
	attributes["public"] = boolString(external)
	attributes["internet_exposed"] = boolString(external && inUse)
	attributes["external_exposure"] = boolString(external && inUse)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-address-"+resourceID, "gcp.compute_address", "gcp/compute_address/v1", payload, attributes)
}

func ComputeBackendBucketEvent(settings Settings, record ComputeBackendBucketRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name, record.BucketName)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	usedByNames, usedByURLs := computeBackendBucketUsedBy(record.UsedBy)
	negativeCachingCodes := computeBackendBucketNegativeCachingCodes(record.CDNPolicy.NegativeCachingPolicy)
	attributes := cloudResourceAttributes(settings, "compute_backend_bucket", resourceID, record.Name, "compute_backend_bucket", location, nil)
	attributes["description"] = record.Description
	attributes["bucket_name"] = record.BucketName
	attributes["storage_bucket"] = record.BucketName
	attributes["cdn_enabled"] = boolString(record.EnableCDN)
	attributes["cache_mode"] = record.CDNPolicy.CacheMode
	attributes["signed_url_keys_count"] = strconv.Itoa(len(record.CDNPolicy.SignedURLKeyNames))
	attributes["signed_url_cache_max_age_sec"] = record.CDNPolicy.SignedURLCacheMaxAge
	attributes["request_coalescing"] = boolString(record.CDNPolicy.RequestCoalescing)
	if record.CDNPolicy.DefaultTTL != 0 {
		attributes["default_ttl_sec"] = strconv.Itoa(record.CDNPolicy.DefaultTTL)
	}
	if record.CDNPolicy.MaxTTL != 0 {
		attributes["max_ttl_sec"] = strconv.Itoa(record.CDNPolicy.MaxTTL)
	}
	if record.CDNPolicy.ClientTTL != 0 {
		attributes["client_ttl_sec"] = strconv.Itoa(record.CDNPolicy.ClientTTL)
	}
	attributes["negative_caching"] = boolString(record.CDNPolicy.NegativeCaching)
	attributes["negative_caching_policy_count"] = strconv.Itoa(len(record.CDNPolicy.NegativeCachingPolicy))
	attributes["negative_caching_codes"] = strings.Join(negativeCachingCodes, ",")
	if record.CDNPolicy.ServeWhileStale != 0 {
		attributes["serve_while_stale_sec"] = strconv.Itoa(record.CDNPolicy.ServeWhileStale)
	}
	attributes["bypass_cache_headers_count"] = strconv.Itoa(len(record.CDNPolicy.BypassCacheOnHeaders))
	attributes["cache_key_query_whitelist_count"] = strconv.Itoa(len(record.CDNPolicy.CacheKeyPolicy.QueryStringWhitelist))
	attributes["cache_key_include_headers_count"] = strconv.Itoa(len(record.CDNPolicy.CacheKeyPolicy.IncludeHTTPHeaders))
	attributes["custom_response_headers_count"] = strconv.Itoa(len(record.CustomResponseHeaders))
	attributes["edge_security_policy"] = lastPathSegment(record.EdgeSecurityPolicy)
	attributes["edge_security_policy_url"] = record.EdgeSecurityPolicy
	attributes["compression_mode"] = record.CompressionMode
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["used_by"] = strings.Join(usedByNames, ",")
	attributes["used_by_urls"] = strings.Join(usedByURLs, ",")
	attributes["used_by_count"] = strconv.Itoa(len(record.UsedBy))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-backend-bucket-"+resourceID, "gcp.compute_backend_bucket", "gcp/compute_backend_bucket/v1", payload, attributes)
}

func ComputeBackendServiceEvent(settings Settings, record ComputeBackendServiceRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeBackendServiceExternal(record.LoadBalancingScheme)
	backendNames, backendURLs, balancingModes, failoverCount := computeBackendServiceBackends(record.Backends)
	healthCheckNames := lastPathSegments(record.HealthChecks)
	attributes := cloudResourceAttributes(settings, "compute_backend_service", resourceID, record.Name, "compute_backend_service", location, record.Labels)
	attributes["description"] = record.Description
	attributes["protocol"] = record.Protocol
	attributes["port_name"] = record.PortName
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["external_load_balancing"] = boolString(external)
	attributes["session_affinity"] = record.SessionAffinity
	attributes["locality_lb_policy"] = record.LocalityLBPolicy
	attributes["timeout_sec"] = strconv.Itoa(record.TimeoutSec)
	attributes["connection_draining_timeout_sec"] = strconv.Itoa(record.ConnectionDraining.DrainingTimeoutSec)
	attributes["cdn_enabled"] = boolString(record.EnableCDN)
	attributes["iap_enabled"] = boolString(record.IAP.Enabled)
	attributes["logging_enabled"] = boolString(record.LogConfig.Enable)
	attributes["log_sample_rate"] = strconv.FormatFloat(record.LogConfig.SampleRate, 'f', -1, 64)
	attributes["health_checks"] = strings.Join(healthCheckNames, ",")
	attributes["health_check_urls"] = strings.Join(record.HealthChecks, ",")
	attributes["health_checks_count"] = strconv.Itoa(len(record.HealthChecks))
	attributes["backend_groups"] = strings.Join(backendNames, ",")
	attributes["backend_group_urls"] = strings.Join(backendURLs, ",")
	attributes["backends_count"] = strconv.Itoa(len(record.Backends))
	attributes["backend_balancing_modes"] = strings.Join(balancingModes, ",")
	attributes["failover_backends_count"] = strconv.Itoa(failoverCount)
	attributes["security_policy"] = lastPathSegment(record.SecurityPolicy)
	attributes["security_policy_url"] = record.SecurityPolicy
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["custom_request_headers_count"] = strconv.Itoa(len(record.CustomRequestHeaders))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-backend-service-"+resourceID, "gcp.compute_backend_service", "gcp/compute_backend_service/v1", payload, attributes)
}

func ComputeInstanceGroupEvent(settings Settings, record ComputeInstanceGroupRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	namedPorts := computeNamedPorts(record.NamedPorts)
	attributes := cloudResourceAttributes(settings, "compute_instance_group", resourceID, record.Name, "compute_instance_group", location, nil)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["size"] = strconv.Itoa(record.Size)
	attributes["named_ports"] = strings.Join(namedPorts, ",")
	attributes["named_ports_count"] = strconv.Itoa(len(record.NamedPorts))
	attributes["backend_group_type"] = "instance_group"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-group-"+resourceID, "gcp.compute_instance_group", "gcp/compute_instance_group/v1", payload, attributes)
}

func ComputeInstanceGroupManagerEvent(settings Settings, record ComputeInstanceGroupManagerRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	namedPorts := computeNamedPorts(record.NamedPorts)
	healthChecks := computeAutoHealingHealthChecks(record.AutoHealingPolicies)
	attributes := cloudResourceAttributes(settings, "compute_instance_group_manager", resourceID, record.Name, "compute_instance_group_manager", location, nil)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["base_instance_name"] = record.BaseInstanceName
	attributes["instance_template"] = lastPathSegment(record.InstanceTemplate)
	attributes["instance_template_url"] = record.InstanceTemplate
	attributes["target_size"] = strconv.Itoa(record.TargetSize)
	attributes["target_pools"] = strings.Join(lastPathSegments(record.TargetPools), ",")
	attributes["target_pool_urls"] = strings.Join(record.TargetPools, ",")
	attributes["target_pools_count"] = strconv.Itoa(len(record.TargetPools))
	attributes["named_ports"] = strings.Join(namedPorts, ",")
	attributes["named_ports_count"] = strconv.Itoa(len(record.NamedPorts))
	attributes["auto_healing_health_checks"] = strings.Join(lastPathSegments(healthChecks), ",")
	attributes["auto_healing_health_check_urls"] = strings.Join(healthChecks, ",")
	attributes["auto_healing_policies_count"] = strconv.Itoa(len(record.AutoHealingPolicies))
	attributes["current_none"] = strconv.Itoa(record.CurrentActions.None)
	attributes["is_stable"] = boolString(record.Status.IsStable)
	attributes["version_target_reached"] = boolString(record.Status.VersionTarget.IsReached)
	attributes["update_policy_type"] = record.UpdatePolicy.Type
	attributes["minimal_action"] = record.UpdatePolicy.MinimalAction
	attributes["replacement_method"] = record.UpdatePolicy.ReplacementMethod
	attributes["distribution_zones"] = strings.Join(computeDistributionZones(record.DistributionPolicy), ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-group-manager-"+resourceID, "gcp.compute_instance_group_manager", "gcp/compute_instance_group_manager/v1", payload, attributes)
}

func ComputeInstanceTemplateEvent(settings Settings, record ComputeInstanceTemplateRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	network := firstTemplateNetworkInterface(record.Properties)
	serviceAccounts := computeTemplateServiceAccounts(record.Properties)
	public := computeTemplatePublic(record.Properties)
	attributes := cloudResourceAttributes(settings, "compute_instance_template", resourceID, record.Name, "compute_instance_template", "global", record.Properties.Labels)
	attributes["description"] = record.Description
	attributes["machine_type"] = lastPathSegment(record.Properties.MachineType)
	attributes["network"] = lastPathSegment(network.Network)
	attributes["network_url"] = network.Network
	attributes["subnet"] = lastPathSegment(network.Subnetwork)
	attributes["subnet_url"] = network.Subnetwork
	attributes["subnetwork"] = lastPathSegment(network.Subnetwork)
	attributes["subnetwork_url"] = network.Subnetwork
	attributes["service_account_email"] = firstString(serviceAccounts)
	attributes["service_accounts"] = strings.Join(serviceAccounts, ",")
	attributes["service_accounts_count"] = strconv.Itoa(len(serviceAccounts))
	attributes["runtime_identity"] = firstString(serviceAccounts)
	attributes["network_tags"] = strings.Join(record.Properties.Tags.Items, ",")
	attributes["security_tags"] = strings.Join(record.Properties.Tags.Items, ",")
	attributes["disks_count"] = strconv.Itoa(len(record.Properties.Disks))
	attributes["kms_key_name"] = computeTemplateBootDiskKMS(record.Properties)
	attributes["secure_boot"] = boolString(record.Properties.ShieldedInstanceConfig.EnableSecureBoot)
	attributes["integrity_monitoring"] = boolString(record.Properties.ShieldedInstanceConfig.EnableIntegrityMonitoring)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = boolString(public)
	attributes["external_exposure"] = boolString(public)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-template-"+resourceID, "gcp.compute_instance_template", "gcp/compute_instance_template/v1", payload, attributes)
}

func ComputeNetworkEndpointGroupEvent(settings Settings, record ComputeNetworkEndpointGroupRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_network_endpoint_group", resourceID, record.Name, "compute_network_endpoint_group", location, record.Annotations)
	attributes["description"] = record.Description
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = lastPathSegment(record.Region)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["network_endpoint_type"] = record.NetworkEndpointType
	attributes["endpoint_type"] = record.NetworkEndpointType
	attributes["default_port"] = strconv.Itoa(record.DefaultPort)
	attributes["size"] = strconv.Itoa(record.Size)
	attributes["psc_target_service"] = record.PscTargetService
	attributes["cloud_run_service"] = record.CloudRun.Service
	attributes["cloud_function"] = record.CloudFunction.Function
	attributes["app_engine_service"] = record.AppEngine.Service
	attributes["backend_group_type"] = "network_endpoint_group"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-endpoint-group-"+resourceID, "gcp.compute_network_endpoint_group", "gcp/compute_network_endpoint_group/v1", payload, attributes)
}

func ComputeRouterEvent(settings Settings, record ComputeRouterRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	natNames, natIPs, natModes, natLogging := computeRouterNATs(record.NATs)
	interfaces := computeRouterInterfaces(record.Interfaces)
	peerNames, peerASNs := computeRouterPeers(record.BGPPeers)
	attributes := cloudResourceAttributes(settings, "compute_router", resourceID, record.Name, "compute_router", location, nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ncc_gateway"] = lastPathSegment(record.NCCGateway)
	attributes["ncc_gateway_url"] = record.NCCGateway
	attributes["asn"] = strconv.FormatInt(record.BGP.ASN, 10)
	attributes["advertise_mode"] = record.BGP.AdvertiseMode
	attributes["advertised_groups"] = strings.Join(record.BGP.AdvertisedGroups, ",")
	attributes["keepalive_interval"] = strconv.Itoa(record.BGP.KeepaliveInterval)
	attributes["interfaces"] = strings.Join(interfaces, ",")
	attributes["interfaces_count"] = strconv.Itoa(len(record.Interfaces))
	attributes["bgp_peers"] = strings.Join(peerNames, ",")
	attributes["bgp_peer_asns"] = strings.Join(peerASNs, ",")
	attributes["bgp_peers_count"] = strconv.Itoa(len(record.BGPPeers))
	attributes["nats"] = strings.Join(natNames, ",")
	attributes["nats_count"] = strconv.Itoa(len(record.NATs))
	attributes["nat_ip_allocate_options"] = strings.Join(natModes, ",")
	attributes["nat_ips"] = strings.Join(lastPathSegments(natIPs), ",")
	attributes["nat_ip_urls"] = strings.Join(natIPs, ",")
	attributes["nat_logging_enabled"] = boolString(natLogging)
	attributes["encrypted_interconnect_router"] = boolString(record.EncryptedInterconnectRouter)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-router-"+resourceID, "gcp.compute_router", "gcp/compute_router/v1", payload, attributes)
}

func ComputeVPNGatewayEvent(settings Settings, record ComputeVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_vpn_gateway", resourceID, record.Name, "compute_vpn_gateway", location, record.Labels)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["gateway_ip_version"] = record.GatewayIPVersion
	attributes["stack_type"] = record.StackType
	attributes["interfaces_count"] = strconv.Itoa(len(record.VPNInterfaces))
	attributes["interface_ips"] = strings.Join(computeVPNGatewayInterfaceIPs(record.VPNInterfaces), ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-vpn-gateway-"+resourceID, "gcp.compute_vpn_gateway", "gcp/compute_vpn_gateway/v1", payload, attributes)
}

func ComputeTargetVPNGatewayEvent(settings Settings, record ComputeTargetVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_target_vpn_gateway", resourceID, record.Name, "compute_target_vpn_gateway", location, record.Labels)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["status"] = record.Status
	attributes["tunnels"] = strings.Join(lastPathSegments(record.Tunnels), ",")
	attributes["tunnel_urls"] = strings.Join(record.Tunnels, ",")
	attributes["tunnels_count"] = strconv.Itoa(len(record.Tunnels))
	attributes["forwarding_rules"] = strings.Join(lastPathSegments(record.ForwardingRules), ",")
	attributes["forwarding_rule_urls"] = strings.Join(record.ForwardingRules, ",")
	attributes["forwarding_rules_count"] = strconv.Itoa(len(record.ForwardingRules))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-vpn-gateway-"+resourceID, "gcp.compute_target_vpn_gateway", "gcp/compute_target_vpn_gateway/v1", payload, attributes)
}

func ComputeVPNTunnelEvent(settings Settings, record ComputeVPNTunnelRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_vpn_tunnel", resourceID, record.Name, "compute_vpn_tunnel", location, record.Labels)
	attributes["description"] = record.Description
	attributes["status"] = record.Status
	attributes["detailed_status"] = record.DetailedStatus
	attributes["ike_version"] = strconv.Itoa(record.IKEVersion)
	attributes["peer_ip"] = record.PeerIP
	attributes["peer_external_gateway"] = lastPathSegment(record.PeerExternalGateway)
	attributes["peer_external_gateway_url"] = record.PeerExternalGateway
	attributes["peer_gcp_gateway"] = lastPathSegment(record.PeerGCPGateway)
	attributes["peer_gcp_gateway_url"] = record.PeerGCPGateway
	attributes["target_vpn_gateway"] = lastPathSegment(record.TargetVPNGateway)
	attributes["target_vpn_gateway_url"] = record.TargetVPNGateway
	attributes["vpn_gateway"] = lastPathSegment(record.VPNGateway)
	attributes["vpn_gateway_url"] = record.VPNGateway
	attributes["vpn_gateway_interface"] = strconv.Itoa(record.VPNGatewayInterface)
	attributes["router"] = lastPathSegment(record.Router)
	attributes["router_url"] = record.Router
	attributes["local_traffic_selectors"] = strings.Join(record.LocalTrafficSelector, ",")
	attributes["remote_traffic_selectors"] = strings.Join(record.RemoteTrafficSelector, ",")
	attributes["shared_secret_configured"] = boolString(record.SharedSecretHash != "")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-vpn-tunnel-"+resourceID, "gcp.compute_vpn_tunnel", "gcp/compute_vpn_tunnel/v1", payload, attributes)
}

func ComputeInterconnectAttachmentEvent(settings Settings, record ComputeInterconnectAttachmentRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	attributes := cloudResourceAttributes(settings, "compute_interconnect_attachment", resourceID, record.Name, "compute_interconnect_attachment", location, record.Labels)
	attributes["description"] = record.Description
	attributes["router"] = lastPathSegment(record.Router)
	attributes["router_url"] = record.Router
	attributes["interconnect"] = lastPathSegment(record.Interconnect)
	attributes["interconnect_url"] = record.Interconnect
	attributes["attachment_type"] = record.Type
	attributes["type"] = record.Type
	attributes["admin_enabled"] = boolString(record.AdminEnabled)
	attributes["operational_status"] = record.OperationalStatus
	attributes["status"] = firstNonEmpty(record.OperationalStatus, record.State)
	attributes["state"] = record.State
	attributes["bandwidth"] = record.Bandwidth
	attributes["edge_availability_domain"] = record.EdgeAvailabilityDomain
	if record.VlanTag8021q != 0 {
		attributes["vlan_tag_8021q"] = strconv.Itoa(record.VlanTag8021q)
	}
	if record.MTU != 0 {
		attributes["mtu"] = strconv.Itoa(record.MTU)
	}
	attributes["encryption"] = record.Encryption
	attributes["encrypted"] = boolString(record.Encryption != "" && !strings.EqualFold(record.Encryption, "NONE"))
	attributes["stack_type"] = record.StackType
	attributes["cloud_router_ip_address"] = record.CloudRouterIPAddress
	attributes["customer_router_ip_address"] = record.CustomerRouterIPAddress
	attributes["ipsec_internal_addresses"] = strings.Join(lastPathSegments(record.IPSecInternalAddresses), ",")
	attributes["ipsec_internal_address_urls"] = strings.Join(record.IPSecInternalAddresses, ",")
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPzs)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-interconnect-attachment-"+resourceID, "gcp.compute_interconnect_attachment", "gcp/compute_interconnect_attachment/v1", payload, attributes)
}

func ComputeExternalVPNGatewayEvent(settings Settings, record ComputeExternalVPNGatewayRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	ipv4, ipv6 := computeExternalVPNGatewayInterfaceIPs(record.Interfaces)
	attributes := cloudResourceAttributes(settings, "compute_external_vpn_gateway", resourceID, record.Name, "compute_external_vpn_gateway", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["redundancy_type"] = record.RedundancyType
	attributes["interfaces_count"] = strconv.Itoa(len(record.Interfaces))
	attributes["interface_ips"] = strings.Join(ipv4, ",")
	attributes["interface_ipv6_addresses"] = strings.Join(ipv6, ",")
	attributes["public"] = boolString(len(ipv4) != 0 || len(ipv6) != 0)
	attributes["external_exposure"] = boolString(len(ipv4) != 0 || len(ipv6) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-external-vpn-gateway-"+resourceID, "gcp.compute_external_vpn_gateway", "gcp/compute_external_vpn_gateway/v1", payload, attributes)
}

func ComputeInterconnectEvent(settings Settings, record ComputeInterconnectRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := "global"
	attachments := lastPathSegments(record.InterconnectAttachments)
	outages := computeInterconnectOutages(record.ExpectedOutages)
	attributes := cloudResourceAttributes(settings, "compute_interconnect", resourceID, record.Name, "compute_interconnect", location, record.Labels)
	attributes["description"] = record.Description
	attributes["interconnect_location"] = lastPathSegment(record.Location)
	attributes["interconnect_location_url"] = record.Location
	attributes["remote_location"] = lastPathSegment(record.RemoteLocation)
	attributes["remote_location_url"] = record.RemoteLocation
	attributes["link_type"] = record.LinkType
	attributes["interconnect_type"] = record.InterconnectType
	attributes["admin_enabled"] = boolString(record.AdminEnabled)
	attributes["operational_status"] = record.OperationalStatus
	attributes["status"] = firstNonEmpty(record.OperationalStatus, record.State)
	attributes["state"] = record.State
	attributes["requested_link_count"] = strconv.Itoa(record.RequestedLinkCount)
	attributes["provisioned_link_count"] = strconv.Itoa(record.ProvisionedLinkCount)
	attributes["attachments"] = strings.Join(attachments, ",")
	attributes["attachment_urls"] = strings.Join(record.InterconnectAttachments, ",")
	attributes["attachments_count"] = strconv.Itoa(len(record.InterconnectAttachments))
	attributes["peer_ip_address"] = record.PeerIPAddress
	attributes["google_ip_address"] = record.GoogleIPAddress
	attributes["expected_outages"] = strings.Join(outages, ",")
	attributes["expected_outages_count"] = strconv.Itoa(len(record.ExpectedOutages))
	attributes["macsec_enabled"] = boolString(record.MACsecEnabled)
	attributes["macsec_fail_open"] = boolString(record.MACsec.FailOpen)
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPzs)
	attributes["requested_features"] = strings.Join(record.RequestedFeatures, ",")
	attributes["available_features"] = strings.Join(record.AvailableFeatures, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-interconnect-"+resourceID, "gcp.compute_interconnect", "gcp/compute_interconnect/v1", payload, attributes)
}

func ComputePacketMirroringEvent(settings Settings, record ComputePacketMirroringRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	network := computePacketMirroringReferenceURL(record.Network)
	collector := firstNonEmpty(record.CollectorILB.CanonicalURL, record.CollectorILB.URL)
	instances := computePacketMirroringReferenceURLs(record.MirroredResources.Instances)
	subnetworks := computePacketMirroringReferenceURLs(record.MirroredResources.Subnetworks)
	enabled := !strings.EqualFold(record.Enable, "FALSE") && !strings.EqualFold(record.Enable, "DISABLED")
	attributes := cloudResourceAttributes(settings, "compute_packet_mirroring", resourceID, record.Name, "compute_packet_mirroring", location, nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(network)
	attributes["network_url"] = network
	attributes["priority"] = strconv.Itoa(record.Priority)
	attributes["collector_ilb"] = lastPathSegment(collector)
	attributes["collector_ilb_url"] = collector
	attributes["mirrored_instances"] = strings.Join(lastPathSegments(instances), ",")
	attributes["mirrored_instance_urls"] = strings.Join(instances, ",")
	attributes["mirrored_subnetworks"] = strings.Join(lastPathSegments(subnetworks), ",")
	attributes["mirrored_subnetwork_urls"] = strings.Join(subnetworks, ",")
	attributes["mirrored_tags"] = strings.Join(record.MirroredResources.Tags, ",")
	attributes["filter_cidr_ranges"] = strings.Join(record.Filter.CIDRRanges, ",")
	attributes["filter_protocols"] = strings.Join(record.Filter.IPProtocols, ",")
	attributes["filter_direction"] = record.Filter.Direction
	attributes["enable"] = record.Enable
	attributes["enabled"] = boolString(enabled)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-packet-mirroring-"+resourceID, "gcp.compute_packet_mirroring", "gcp/compute_packet_mirroring/v1", payload, attributes)
}

func computePacketMirroringReferenceURL(ref ComputePacketMirroringReference) string {
	return firstNonEmpty(ref.CanonicalURL, ref.URL)
}

func computePacketMirroringReferenceURLs(refs []ComputePacketMirroringReference) []string {
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if url := computePacketMirroringReferenceURL(ref); url != "" {
			urls = append(urls, url)
		}
	}
	return urls
}

func ComputeNetworkFirewallPolicyEvent(settings Settings, record ComputeNetworkFirewallPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.SelfLinkWithID, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	summary := computeFirewallPolicyRuleSummary(record.Rules)
	attributes := cloudResourceAttributes(settings, "compute_network_firewall_policy", resourceID, firstNonEmpty(record.DisplayName, record.ShortName, record.Name), "compute_network_firewall_policy", location, nil)
	attributes["description"] = record.Description
	attributes["policy_type"] = record.PolicyType
	attributes["parent"] = record.Parent
	attributes["short_name"] = record.ShortName
	attributes["display_name"] = record.DisplayName
	attributes["rules_count"] = strconv.Itoa(len(record.Rules))
	attributes["packet_mirroring_rules_count"] = strconv.Itoa(len(record.PacketMirroringRules))
	attributes["associations"] = strings.Join(computeFirewallPolicyAssociations(record.Associations), ",")
	attributes["associations_count"] = strconv.Itoa(len(record.Associations))
	attributes["rule_actions"] = strings.Join(summary.Actions, ",")
	attributes["rule_priorities"] = strings.Join(summary.Priorities, ",")
	attributes["source_ranges"] = strings.Join(summary.SourceRanges, ",")
	attributes["destination_ranges"] = strings.Join(summary.DestinationRanges, ",")
	attributes["layer4_configs"] = strings.Join(summary.Layer4Configs, ",")
	attributes["target_resources"] = strings.Join(summary.TargetResources, ",")
	attributes["target_service_accounts"] = strings.Join(summary.TargetServiceAccounts, ",")
	attributes["logging_enabled"] = boolString(summary.LoggingEnabled)
	attributes["disabled_rules_count"] = strconv.Itoa(summary.DisabledCount)
	if record.RuleTupleCount != 0 {
		attributes["rule_tuple_count"] = strconv.Itoa(record.RuleTupleCount)
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-firewall-policy-"+resourceID, "gcp.compute_network_firewall_policy", "gcp/compute_network_firewall_policy/v1", payload, attributes)
}

func ComputeHealthCheckEvent(settings Settings, record ComputeHealthCheckRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	healthCheckType, probe := computeHealthCheckProbe(record)
	attributes := cloudResourceAttributes(settings, "compute_health_check", resourceID, record.Name, "compute_health_check", location, nil)
	attributes["description"] = record.Description
	attributes["type"] = healthCheckType
	attributes["protocol"] = healthCheckType
	attributes["check_interval_sec"] = strconv.Itoa(record.CheckIntervalSec)
	attributes["timeout_sec"] = strconv.Itoa(record.TimeoutSec)
	attributes["healthy_threshold"] = strconv.Itoa(record.HealthyThreshold)
	attributes["unhealthy_threshold"] = strconv.Itoa(record.UnhealthyThreshold)
	if probe.Port != 0 {
		attributes["port"] = strconv.Itoa(probe.Port)
	}
	attributes["port_name"] = probe.PortName
	attributes["port_specification"] = probe.PortSpecification
	attributes["host"] = probe.Host
	attributes["request_path"] = probe.RequestPath
	attributes["proxy_header"] = probe.ProxyHeader
	attributes["grpc_service_name"] = probe.GRPCServiceName
	attributes["request_configured"] = boolString(probe.Request != "")
	attributes["response_configured"] = boolString(probe.Response != "")
	attributes["source_regions"] = strings.Join(record.SourceRegions, ",")
	attributes["source_regions_count"] = strconv.Itoa(len(record.SourceRegions))
	attributes["logging_enabled"] = boolString(record.LogConfig.Enable)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-health-check-"+resourceID, "gcp.compute_health_check", "gcp/compute_health_check/v1", payload, attributes)
}

func ComputeSecurityPolicyEvent(settings Settings, record ComputeSecurityPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	rules := computeSecurityPolicyRules(record.Rules)
	associatedNames, associatedURLs := computeSecurityPolicyAssociations(record.Associations)
	attributes := cloudResourceAttributes(settings, "compute_security_policy", resourceID, record.Name, "compute_security_policy", location, record.Labels)
	attributes["description"] = record.Description
	attributes["security_policy_type"] = record.Type
	attributes["policy_type"] = record.Type
	attributes["fingerprint"] = record.Fingerprint
	attributes["rules_count"] = strconv.Itoa(len(record.Rules))
	attributes["preview_rules_count"] = strconv.Itoa(rules.previewCount)
	attributes["allow_rules_count"] = strconv.Itoa(rules.allowCount)
	attributes["deny_rules_count"] = strconv.Itoa(rules.denyCount)
	attributes["throttle_rules_count"] = strconv.Itoa(rules.throttleCount)
	attributes["rate_based_ban_rules_count"] = strconv.Itoa(rules.rateBasedBanCount)
	attributes["redirect_rules_count"] = strconv.Itoa(rules.redirectCount)
	attributes["custom_expression_rules_count"] = strconv.Itoa(rules.customExpressionCount)
	attributes["default_rule_action"] = rules.defaultAction
	attributes["rule_actions"] = strings.Join(rules.actions, ",")
	attributes["versioned_expressions"] = strings.Join(rules.versionedExpressions, ",")
	attributes["source_ip_ranges"] = strings.Join(rules.sourceIPRanges, ",")
	attributes["custom_expressions"] = strings.Join(rules.customExpressions, "\n")
	attributes["adaptive_protection_enabled"] = boolString(record.AdaptiveProtectionConfig.Layer7DDoSDefenseConfig.Enable)
	attributes["json_parsing"] = record.AdvancedOptionsConfig.JSONParsing
	attributes["log_level"] = record.AdvancedOptionsConfig.LogLevel
	attributes["user_ip_request_headers"] = strings.Join(record.AdvancedOptionsConfig.UserIPRequestHeaders, ",")
	attributes["associations_count"] = strconv.Itoa(len(record.Associations))
	attributes["associated_resources"] = strings.Join(associatedNames, ",")
	attributes["associated_resource_urls"] = strings.Join(associatedURLs, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-security-policy-"+resourceID, "gcp.compute_security_policy", "gcp/compute_security_policy/v1", payload, attributes)
}

func ComputeURLMapEvent(settings Settings, record ComputeURLMapRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	routes := computeURLMapRoutes(record)
	attributes := cloudResourceAttributes(settings, "compute_url_map", resourceID, record.Name, "compute_url_map", location, nil)
	attributes["description"] = record.Description
	attributes["default_service"] = lastPathSegment(record.DefaultService)
	attributes["default_service_url"] = record.DefaultService
	attributes["host_rules_count"] = strconv.Itoa(len(record.HostRules))
	attributes["hosts"] = strings.Join(routes.hosts, ",")
	attributes["path_matchers"] = strings.Join(routes.pathMatchers, ",")
	attributes["path_matchers_count"] = strconv.Itoa(len(record.PathMatchers))
	attributes["paths"] = strings.Join(routes.paths, ",")
	attributes["path_rules_count"] = strconv.Itoa(routes.pathRulesCount)
	attributes["route_rules_count"] = strconv.Itoa(routes.routeRulesCount)
	attributes["redirect_rules_count"] = strconv.Itoa(routes.redirectRulesCount)
	attributes["weighted_backend_services_count"] = strconv.Itoa(routes.weightedBackendServicesCount)
	attributes["backend_services"] = strings.Join(routes.backendNames, ",")
	attributes["backend_service_urls"] = strings.Join(routes.backendURLs, ",")
	attributes["backend_resources"] = strings.Join(routes.backendNames, ",")
	attributes["backend_resource_urls"] = strings.Join(routes.backendURLs, ",")
	attributes["tests_count"] = strconv.Itoa(len(record.Tests))
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-url-map-"+resourceID, "gcp.compute_url_map", "gcp/compute_url_map/v1", payload, attributes)
}

func ComputeTargetHTTPProxyEvent(settings Settings, record ComputeTargetHTTPProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_target_http_proxy", resourceID, record.Name, "compute_target_http_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "HTTP"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	if record.HTTPKeepAliveTimeoutSec != 0 {
		attributes["http_keep_alive_timeout_sec"] = strconv.Itoa(record.HTTPKeepAliveTimeoutSec)
	}
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-http-proxy-"+resourceID, "gcp.compute_target_http_proxy", "gcp/compute_target_http_proxy/v1", payload, attributes)
}

func ComputeTargetHTTPSProxyEvent(settings Settings, record ComputeTargetHTTPSProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	certificates := lastPathSegments(record.SSLCertificates)
	attributes := cloudResourceAttributes(settings, "compute_target_https_proxy", resourceID, record.Name, "compute_target_https_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "HTTPS"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["ssl_certificates"] = strings.Join(certificates, ",")
	attributes["ssl_certificate_urls"] = strings.Join(record.SSLCertificates, ",")
	attributes["ssl_certificates_count"] = strconv.Itoa(len(record.SSLCertificates))
	attributes["certificate_map"] = lastPathSegment(record.CertificateMap)
	attributes["certificate_map_url"] = record.CertificateMap
	attributes["certificates_configured"] = boolString(len(record.SSLCertificates) != 0 || record.CertificateMap != "")
	attributes["quic_override"] = record.QUICOverride
	attributes["ssl_policy"] = lastPathSegment(record.SSLPolicy)
	attributes["ssl_policy_url"] = record.SSLPolicy
	attributes["server_tls_policy"] = lastPathSegment(record.ServerTLSPolicy)
	attributes["server_tls_policy_url"] = record.ServerTLSPolicy
	attributes["authorization_policy"] = lastPathSegment(record.AuthorizationPolicy)
	attributes["authorization_policy_url"] = record.AuthorizationPolicy
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	attributes["tls_enabled"] = "true"
	if record.HTTPKeepAliveTimeoutSec != 0 {
		attributes["http_keep_alive_timeout_sec"] = strconv.Itoa(record.HTTPKeepAliveTimeoutSec)
	}
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-https-proxy-"+resourceID, "gcp.compute_target_https_proxy", "gcp/compute_target_https_proxy/v1", payload, attributes)
}

func ComputeTargetSSLProxyEvent(settings Settings, record ComputeTargetSSLProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	certificates := lastPathSegments(record.SSLCertificates)
	attributes := cloudResourceAttributes(settings, "compute_target_ssl_proxy", resourceID, record.Name, "compute_target_ssl_proxy", "global", nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "SSL"
	attributes["backend_service"] = lastPathSegment(record.Service)
	attributes["backend_service_url"] = record.Service
	attributes["service"] = lastPathSegment(record.Service)
	attributes["service_url"] = record.Service
	attributes["ssl_certificates"] = strings.Join(certificates, ",")
	attributes["ssl_certificate_urls"] = strings.Join(record.SSLCertificates, ",")
	attributes["ssl_certificates_count"] = strconv.Itoa(len(record.SSLCertificates))
	attributes["certificate_map"] = lastPathSegment(record.CertificateMap)
	attributes["certificate_map_url"] = record.CertificateMap
	attributes["certificates_configured"] = boolString(len(record.SSLCertificates) != 0 || record.CertificateMap != "")
	attributes["ssl_policy"] = lastPathSegment(record.SSLPolicy)
	attributes["ssl_policy_url"] = record.SSLPolicy
	attributes["proxy_header"] = record.ProxyHeader
	attributes["tls_enabled"] = "true"
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-ssl-proxy-"+resourceID, "gcp.compute_target_ssl_proxy", "gcp/compute_target_ssl_proxy/v1", payload, attributes)
}

func ComputeTargetTCPProxyEvent(settings Settings, record ComputeTargetTCPProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	external := computeBackendServiceExternal(record.LoadBalancingScheme)
	attributes := cloudResourceAttributes(settings, "compute_target_tcp_proxy", resourceID, record.Name, "compute_target_tcp_proxy", location, nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "TCP"
	attributes["backend_service"] = lastPathSegment(record.Service)
	attributes["backend_service_url"] = record.Service
	attributes["service"] = lastPathSegment(record.Service)
	attributes["service_url"] = record.Service
	attributes["proxy_header"] = record.ProxyHeader
	attributes["proxy_bind"] = boolString(record.ProxyBind)
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["external_load_balancing"] = boolString(external)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-tcp-proxy-"+resourceID, "gcp.compute_target_tcp_proxy", "gcp/compute_target_tcp_proxy/v1", payload, attributes)
}

func ComputeTargetGRPCProxyEvent(settings Settings, record ComputeTargetGRPCProxyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_target_grpc_proxy", resourceID, record.Name, "compute_target_grpc_proxy", "global", nil)
	attributes["description"] = record.Description
	attributes["protocol"] = "GRPC"
	attributes["url_map"] = lastPathSegment(record.URLMap)
	attributes["url_map_url"] = record.URLMap
	attributes["validate_for_proxyless"] = boolString(record.ValidateForProxyless)
	attributes["proxyless_validation"] = boolString(record.ValidateForProxyless)
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-target-grpc-proxy-"+resourceID, "gcp.compute_target_grpc_proxy", "gcp/compute_target_grpc_proxy/v1", payload, attributes)
}

func ComputeSSLPolicyEvent(settings Settings, record ComputeSSLPolicyRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	attributes := cloudResourceAttributes(settings, "compute_ssl_policy", resourceID, record.Name, "compute_ssl_policy", location, nil)
	attributes["description"] = record.Description
	attributes["profile"] = record.Profile
	attributes["min_tls_version"] = record.MinTLSVersion
	attributes["enabled_features"] = strings.Join(record.EnabledFeatures, ",")
	attributes["enabled_features_count"] = strconv.Itoa(len(record.EnabledFeatures))
	attributes["custom_features"] = strings.Join(record.CustomFeatures, ",")
	attributes["custom_features_count"] = strconv.Itoa(len(record.CustomFeatures))
	attributes["custom_profile"] = boolString(strings.EqualFold(record.Profile, "CUSTOM"))
	attributes["post_quantum_key_exchange"] = record.PostQuantumKeyExchange
	attributes["fingerprint"] = record.Fingerprint
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-ssl-policy-"+resourceID, "gcp.compute_ssl_policy", "gcp/compute_ssl_policy/v1", payload, attributes)
}

func ComputeSSLCertificateEvent(settings Settings, record ComputeSSLCertificateRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	certificateType := firstNonEmpty(record.Type, computeSSLCertificateType(record))
	managedDomains := append([]string(nil), record.Managed.Domains...)
	domainStatuses := computeSSLCertificateDomainStatuses(record.Managed.DomainStatus)
	attributes := cloudResourceAttributes(settings, "compute_ssl_certificate", resourceID, record.Name, "compute_ssl_certificate", location, nil)
	attributes["description"] = record.Description
	attributes["certificate_type"] = certificateType
	attributes["type"] = certificateType
	attributes["managed"] = boolString(certificateType == "MANAGED" || len(managedDomains) != 0 || record.Managed.Status != "")
	attributes["self_managed"] = boolString(certificateType == "SELF_MANAGED" || record.SelfManaged.Certificate != "")
	attributes["managed_status"] = record.Managed.Status
	attributes["managed_domains"] = strings.Join(managedDomains, ",")
	attributes["managed_domains_count"] = strconv.Itoa(len(managedDomains))
	attributes["domain_statuses"] = strings.Join(domainStatuses, ",")
	attributes["subject_alternative_names"] = strings.Join(record.SubjectAlternativeNames, ",")
	attributes["sans"] = strings.Join(record.SubjectAlternativeNames, ",")
	attributes["san_count"] = strconv.Itoa(len(record.SubjectAlternativeNames))
	attributes["expire_time"] = record.ExpireTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-ssl-certificate-"+resourceID, "gcp.compute_ssl_certificate", "gcp/compute_ssl_certificate/v1", payload, attributes)
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

func ComputeFirewallEvent(settings Settings, record ComputeFirewallRecord) (*primitives.Event, error) {
	allowed := computeFirewallPrimaryAllowed(record)
	attributes := cloudResourceAttributes(settings, "compute_firewall", firstNonEmpty(record.ID, record.Name), record.Name, "compute_firewall", "global", nil)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["direction"] = record.Direction
	attributes["disabled"] = boolString(record.Disabled)
	attributes["source_ranges"] = strings.Join(record.SourceRanges, ",")
	attributes["target_tags"] = strings.Join(record.TargetTags, ",")
	attributes["target_service_accounts"] = strings.Join(record.TargetServiceAccounts, ",")
	attributes["protocol"] = allowed.IPProtocol
	attributes["ports"] = strings.Join(allowed.Ports, ",")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-firewall-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_firewall", "gcp/compute_firewall/v1", payload, attributes)
}

func ComputeRouteEvent(settings Settings, record ComputeRouteRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	nextHopType, nextHopURL, nextHop := computeRouteNextHop(record)
	defaultRoute := record.DestRange == "0.0.0.0/0" || record.DestRange == "::/0"
	internetEgress := defaultRoute && strings.Contains(nextHopURL, "default-internet-gateway")
	attributes := cloudResourceAttributes(settings, "compute_route", resourceID, record.Name, "compute_route", "global", nil)
	attributes["description"] = record.Description
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["destination_range"] = record.DestRange
	attributes["dest_range"] = record.DestRange
	attributes["priority"] = strconv.Itoa(record.Priority)
	attributes["route_type"] = record.RouteType
	attributes["route_status"] = record.RouteStatus
	attributes["status"] = record.RouteStatus
	attributes["target_tags"] = strings.Join(record.Tags, ",")
	attributes["next_hop_type"] = nextHopType
	attributes["next_hop"] = nextHop
	attributes["next_hop_url"] = nextHopURL
	attributes["next_hop_ip"] = record.NextHopIP
	attributes["next_hop_origin"] = record.NextHopOrigin
	if record.NextHopMed != 0 {
		attributes["next_hop_med"] = strconv.Itoa(record.NextHopMed)
	}
	attributes["default_route"] = boolString(defaultRoute)
	attributes["internet_egress"] = boolString(internetEgress)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-route-"+resourceID, "gcp.compute_route", "gcp/compute_route/v1", payload, attributes)
}

func ComputeForwardingRuleEvent(settings Settings, record ComputeForwardingRuleRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	location := lastPathSegment(record.Region)
	if location == "" {
		location = "global"
	}
	targetType, targetURL, targetName := computeForwardingRuleTarget(record)
	external := computeForwardingRuleExternal(record.LoadBalancingScheme)
	attributes := cloudResourceAttributes(settings, "compute_forwarding_rule", resourceID, record.Name, "compute_forwarding_rule", location, record.Labels)
	attributes["description"] = record.Description
	attributes["ip_address"] = record.IPAddress
	attributes["ip_protocol"] = record.IPProtocol
	attributes["ip_version"] = record.IPVersion
	attributes["load_balancing_scheme"] = record.LoadBalancingScheme
	attributes["scheme"] = record.LoadBalancingScheme
	attributes["network_tier"] = record.NetworkTier
	attributes["port_range"] = record.PortRange
	attributes["ports"] = strings.Join(record.Ports, ",")
	attributes["all_ports"] = boolString(record.AllPorts)
	attributes["allow_global_access"] = boolString(record.AllowGlobalAccess)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["subnetwork"] = lastPathSegment(record.Subnetwork)
	attributes["subnetwork_url"] = record.Subnetwork
	attributes["target_type"] = targetType
	attributes["target"] = targetName
	attributes["target_url"] = targetURL
	attributes["backend_service"] = lastPathSegment(record.BackendService)
	attributes["backend_service_url"] = record.BackendService
	attributes["service_label"] = record.ServiceLabel
	attributes["service_name"] = record.ServiceName
	attributes["public"] = boolString(external)
	attributes["internet_exposed"] = boolString(external)
	attributes["external_exposure"] = boolString(external)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-forwarding-rule-"+resourceID, "gcp.compute_forwarding_rule", "gcp/compute_forwarding_rule/v1", payload, attributes)
}

func ComputeSubnetworkEvent(settings Settings, record ComputeSubnetworkRecord) (*primitives.Event, error) {
	location := lastPathSegment(record.Region)
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_subnetwork", resourceID, record.Name, "compute_subnetwork", location, record.Labels)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ip_cidr_range"] = record.IPCIDRRange
	attributes["private_ip_google_access"] = boolString(record.PrivateIPGoogleAccess)
	attributes["purpose"] = record.Purpose
	attributes["role"] = record.Role
	attributes["stack_type"] = record.StackType
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-subnetwork-"+resourceID, "gcp.compute_subnetwork", "gcp/compute_subnetwork/v1", payload, attributes)
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

func MonitoringAlertPolicyEvent(settings Settings, record MonitoringAlertPolicyRecord) (*primitives.Event, error) {
	conditionNames, conditionTypes := monitoringAlertConditionSummary(record.Conditions)
	attributes := cloudResourceAttributes(settings, "monitoring_alert_policy", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "monitoring_alert_policy", "global", record.UserLabels)
	attributes["display_name"] = record.DisplayName
	attributes["combiner"] = record.Combiner
	attributes["severity"] = record.Severity
	attributes["conditions"] = strings.Join(conditionNames, ",")
	attributes["conditions_count"] = strconv.Itoa(len(record.Conditions))
	attributes["condition_types"] = strings.Join(conditionTypes, ",")
	attributes["notification_channels"] = strings.Join(lastPathSegments(record.NotificationChannels), ",")
	attributes["notification_channel_urls"] = strings.Join(record.NotificationChannels, ",")
	attributes["notification_channels_count"] = strconv.Itoa(len(record.NotificationChannels))
	attributes["documentation_subject"] = record.Documentation.Subject
	attributes["documentation_mime_type"] = record.Documentation.MimeType
	attributes["documentation_present"] = boolString(record.Documentation.Content != "" || record.Documentation.Subject != "")
	attributes["created_at"] = record.CreationRecord.MutateTime
	attributes["created_by"] = record.CreationRecord.MutatedBy
	attributes["updated_at"] = record.MutationRecord.MutateTime
	attributes["updated_by"] = record.MutationRecord.MutatedBy
	if record.Enabled != nil {
		attributes["enabled"] = boolString(*record.Enabled)
		attributes["disabled"] = boolString(!*record.Enabled)
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-monitoring-alert-policy-"+record.Name, "gcp.monitoring_alert_policy", "gcp/monitoring_alert_policy/v1", payload, attributes)
}

func MonitoringNotificationChannelEvent(settings Settings, record MonitoringNotificationChannelRecord) (*primitives.Event, error) {
	labels := record.UserLabels
	if len(labels) == 0 {
		labels = record.Labels
	}
	attributes := cloudResourceAttributes(settings, "monitoring_notification_channel", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "monitoring_notification_channel", "global", labels)
	attributes["display_name"] = record.DisplayName
	attributes["description"] = record.Description
	attributes["channel_type"] = record.Type
	attributes["verification_status"] = record.VerificationStatus
	attributes["sensitive_labels_present"] = boolString(len(record.SensitiveLabels) != 0)
	attributes["created_at"] = record.CreationRecord.MutateTime
	attributes["created_by"] = record.CreationRecord.MutatedBy
	attributes["updated_at"] = record.MutationRecord.MutateTime
	attributes["updated_by"] = record.MutationRecord.MutatedBy
	if record.Enabled != nil {
		attributes["enabled"] = boolString(*record.Enabled)
		attributes["disabled"] = boolString(!*record.Enabled)
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-monitoring-notification-channel-"+record.Name, "gcp.monitoring_notification_channel", "gcp/monitoring_notification_channel/v1", payload, attributes)
}

func LoggingMetricResourceName(projectID string, record LoggingMetricRecord) string {
	metricName := firstNonEmpty(record.Name, lastPathSegment(record.MetricDescriptor.Name), record.MetricDescriptor.Type)
	if strings.HasPrefix(metricName, "projects/") {
		return metricName
	}
	return "projects/" + projectID + "/metrics/" + metricName
}

func LoggingMetricEvent(settings Settings, record LoggingMetricRecord) (*primitives.Event, error) {
	metricResourceName := LoggingMetricResourceName(settings.ProjectID, record)
	metricName := lastPathSegment(metricResourceName)
	attributes := cloudResourceAttributes(settings, "logging_metric", metricResourceName, metricName, "logging_metric", "global", nil)
	attributes["metric_name"] = metricName
	attributes["description"] = record.Description
	attributes["filter"] = record.Filter
	attributes["disabled"] = boolString(record.Disabled)
	attributes["enabled"] = boolString(!record.Disabled)
	attributes["metric_descriptor_name"] = record.MetricDescriptor.Name
	attributes["metric_type"] = record.MetricDescriptor.Type
	attributes["metric_kind"] = record.MetricDescriptor.MetricKind
	attributes["value_type"] = record.MetricDescriptor.ValueType
	attributes["unit"] = record.MetricDescriptor.Unit
	attributes["label_extractors_count"] = strconv.Itoa(len(record.LabelExtractors))
	attributes["value_extractor_configured"] = boolString(record.ValueExtractor != "")
	attributes["bucket_options_configured"] = boolString(len(record.BucketOptions) != 0)
	attributes["version"] = record.Version
	attributes["created_at"] = record.CreateTime
	attributes["updated_at"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-logging-metric-"+metricName, "gcp.logging_metric", "gcp/logging_metric/v1", payload, attributes)
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

func BigtableInstanceEvent(settings Settings, record BigtableInstanceRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "bigtable_instance", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "bigtable_instance", location, record.Labels)
	attributes["display_name"] = record.DisplayName
	attributes["state"] = record.State
	attributes["status"] = record.State
	attributes["instance_type"] = record.Type
	attributes["type"] = record.Type
	attributes["create_time"] = record.CreateTime
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPZS)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-bigtable-instance-"+record.Name, "gcp.bigtable_instance", "gcp/bigtable_instance/v1", payload, attributes)
}

func BigtableTableEvent(settings Settings, record BigtableTableRecord) (*primitives.Event, error) {
	instanceName := firstNonEmpty(record.InstanceName, parentResourceName(record.Name, "tables"))
	location := locationFromResourceName(instanceName)
	attributes := cloudResourceAttributes(settings, "bigtable_table", record.Name, lastPathSegment(record.Name), "bigtable_table", location, nil)
	attributes["instance_name"] = lastPathSegment(instanceName)
	attributes["instance_url"] = instanceName
	attributes["cluster_states_count"] = strconv.Itoa(len(record.ClusterStates))
	attributes["clusters_count"] = strconv.Itoa(len(record.ClusterStates))
	attributes["column_families_count"] = strconv.Itoa(len(record.ColumnFamilies))
	attributes["granularity"] = record.Granularity
	attributes["deletion_protection"] = boolString(record.DeletionProtection)
	attributes["change_stream_enabled"] = boolString(record.ChangeStreamConfig.RetentionPeriod != "")
	attributes["change_stream_retention_period"] = record.ChangeStreamConfig.RetentionPeriod
	attributes["restore_configured"] = boolString(len(record.RestoreInfo) != 0)
	attributes["automated_backup_policy_configured"] = boolString(len(record.AutomatedBackupPolicy) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"instance_name": instanceName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-bigtable-table-"+record.Name, "gcp.bigtable_table", "gcp/bigtable_table/v1", payload, attributes)
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

func SpannerInstanceEvent(settings Settings, record SpannerInstanceRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Config)
	if location == "" {
		location = locationFromResourceName(record.Name)
	}
	attributes := cloudResourceAttributes(settings, "spanner_instance", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "spanner_instance", location, record.Labels)
	attributes["display_name"] = record.DisplayName
	attributes["config"] = lastPathSegment(record.Config)
	attributes["config_url"] = record.Config
	attributes["node_count"] = strconv.Itoa(record.NodeCount)
	attributes["processing_units"] = strconv.Itoa(record.ProcessingUnits)
	attributes["state"] = record.State
	attributes["status"] = record.State
	attributes["instance_type"] = record.InstanceType
	attributes["endpoint_uris"] = strings.Join(record.EndpointURIs, ",")
	attributes["endpoint_uris_count"] = strconv.Itoa(len(record.EndpointURIs))
	attributes["autoscaling_configured"] = boolString(len(record.AutoscalingConfig) != 0)
	attributes["free_instance"] = boolString(len(record.FreeInstanceMetadata) != 0)
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-spanner-instance-"+record.Name, "gcp.spanner_instance", "gcp/spanner_instance/v1", payload, attributes)
}

func SpannerDatabaseEvent(settings Settings, record SpannerDatabaseRecord) (*primitives.Event, error) {
	instanceName := firstNonEmpty(record.InstanceName, parentResourceName(record.Name, "databases"))
	location := locationFromResourceName(instanceName)
	encryptionType := firstNonEmpty(record.EncryptionConfig.EncryptionType, firstSpannerEncryptionType(record.EncryptionInfo))
	attributes := cloudResourceAttributes(settings, "spanner_database", record.Name, lastPathSegment(record.Name), "spanner_database", location, nil)
	attributes["instance_name"] = lastPathSegment(instanceName)
	attributes["instance_url"] = instanceName
	attributes["state"] = record.State
	attributes["status"] = record.State
	attributes["database_dialect"] = record.DatabaseDialect
	attributes["drop_protection_enabled"] = boolString(record.EnableDropProtection)
	attributes["reconciling"] = boolString(record.Reconciling)
	attributes["version_retention_period"] = record.VersionRetentionPeriod
	attributes["earliest_version_time"] = record.EarliestVersionTime
	attributes["encryption_type"] = encryptionType
	attributes["kms_key_name"] = record.EncryptionConfig.KMSKeyName
	attributes["encryption_info_count"] = strconv.Itoa(len(record.EncryptionInfo))
	attributes["restore_configured"] = boolString(len(record.RestoreInfo) != 0)
	attributes["create_time"] = record.CreateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"instance_name": instanceName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-spanner-database-"+record.Name, "gcp.spanner_database", "gcp/spanner_database/v1", payload, attributes)
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

func computeRouteNextHop(record ComputeRouteRecord) (string, string, string) {
	for _, candidate := range []struct {
		kind string
		url  string
	}{
		{kind: "gateway", url: record.NextHopGateway},
		{kind: "instance", url: record.NextHopInstance},
		{kind: "vpn_gateway", url: record.NextHopVPNGateway},
		{kind: "vpn_tunnel", url: record.NextHopVPNTunnel},
		{kind: "ilb", url: record.NextHopILB},
		{kind: "network", url: record.NextHopNetwork},
		{kind: "peering", url: record.NextHopPeering},
		{kind: "hub", url: record.NextHopHub},
		{kind: "interconnect_attachment", url: record.NextHopInterconnectAttachment},
	} {
		if candidate.url != "" {
			return candidate.kind, candidate.url, lastPathSegment(candidate.url)
		}
	}
	if record.NextHopIP != "" {
		return "ip", record.NextHopIP, record.NextHopIP
	}
	return "", "", ""
}

func firstComputeNetworkInterface(record ComputeInstanceRecord) ComputeNetworkInterface {
	if len(record.NetworkInterfaces) == 0 {
		return ComputeNetworkInterface{}
	}
	return record.NetworkInterfaces[0]
}

func firstComputeServiceAccountEmail(record ComputeInstanceRecord) string {
	for _, account := range record.ServiceAccounts {
		if email := strings.TrimSpace(account.Email); email != "" {
			return email
		}
	}
	return ""
}

func computePublicIP(record ComputeInstanceRecord) string {
	for _, networkInterface := range record.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if ip := strings.TrimSpace(accessConfig.NatIP); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func computeInstanceKMSKey(record ComputeInstanceRecord) string {
	for _, disk := range record.Disks {
		if key := strings.TrimSpace(disk.DiskEncryptionKey.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func computeNamedPorts(ports []ComputeNamedPort) []string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.Name == "" && port.Port == 0 {
			continue
		}
		values = append(values, port.Name+":"+strconv.Itoa(port.Port))
	}
	return values
}

func computeRouterNATs(nats []ComputeRouterNAT) ([]string, []string, []string, bool) {
	names := make([]string, 0, len(nats))
	ips := []string{}
	modes := []string{}
	logging := false
	for _, nat := range nats {
		if nat.Name != "" {
			names = append(names, nat.Name)
		}
		ips = append(ips, nat.NATIPs...)
		if nat.NATIPAllocateOption != "" {
			modes = append(modes, nat.NATIPAllocateOption)
		}
		logging = logging || nat.LogConfig.Enable
	}
	return names, ips, modes, logging
}

func computeRouterInterfaces(interfaces []ComputeRouterIface) []string {
	values := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		target := lastPathSegment(firstNonEmpty(iface.LinkedVPNTunnel, iface.LinkedInterconnectAttachment, iface.Subnetwork))
		if target == "" {
			values = append(values, iface.Name)
			continue
		}
		values = append(values, iface.Name+":"+target)
	}
	return values
}

func computeRouterPeers(peers []ComputeRouterBGPPeer) ([]string, []string) {
	names := make([]string, 0, len(peers))
	asns := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer.Name != "" {
			names = append(names, peer.Name)
		}
		if peer.PeerASN != 0 {
			asns = append(asns, strconv.FormatInt(peer.PeerASN, 10))
		}
	}
	return names, asns
}

func computeVPNGatewayInterfaceIPs(interfaces []ComputeVPNGatewayInterface) []string {
	values := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.IPAddress != "" {
			values = append(values, iface.IPAddress)
		}
	}
	return values
}

func computeExternalVPNGatewayInterfaceIPs(interfaces []ComputeExternalVPNGatewayInterface) ([]string, []string) {
	ipv4 := make([]string, 0, len(interfaces))
	ipv6 := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.IPAddress != "" {
			ipv4 = append(ipv4, iface.IPAddress)
		}
		if iface.IPv6Address != "" {
			ipv6 = append(ipv6, iface.IPv6Address)
		}
	}
	return ipv4, ipv6
}

func computeInterconnectOutages(outages []ComputeInterconnectOutage) []string {
	values := make([]string, 0, len(outages))
	for _, outage := range outages {
		label := firstNonEmpty(outage.Name, outage.IssueType, outage.State)
		if label == "" {
			continue
		}
		if outage.State != "" && outage.State != label {
			label += ":" + outage.State
		}
		values = append(values, label)
	}
	return values
}

type firewallPolicyRuleSummary struct {
	Actions               []string
	Priorities            []string
	SourceRanges          []string
	DestinationRanges     []string
	Layer4Configs         []string
	TargetResources       []string
	TargetServiceAccounts []string
	LoggingEnabled        bool
	DisabledCount         int
}

func computeFirewallPolicyRuleSummary(rules []ComputeFirewallPolicyRule) firewallPolicyRuleSummary {
	var summary firewallPolicyRuleSummary
	for _, rule := range rules {
		if rule.Action != "" {
			summary.Actions = append(summary.Actions, rule.Action)
		}
		if rule.Priority != 0 {
			summary.Priorities = append(summary.Priorities, strconv.Itoa(rule.Priority))
		}
		summary.SourceRanges = append(summary.SourceRanges, rule.Match.SrcIPRanges...)
		summary.DestinationRanges = append(summary.DestinationRanges, rule.Match.DestIPRanges...)
		summary.TargetResources = append(summary.TargetResources, lastPathSegments(rule.TargetResources)...)
		summary.TargetServiceAccounts = append(summary.TargetServiceAccounts, rule.TargetServiceAccounts...)
		summary.Layer4Configs = append(summary.Layer4Configs, computeFirewallPolicyLayer4Configs(rule.Match.Layer4Configs)...)
		summary.LoggingEnabled = summary.LoggingEnabled || rule.EnableLogging
		if rule.Disabled {
			summary.DisabledCount++
		}
	}
	return summary
}

func computeFirewallPolicyLayer4Configs(configs []ComputeFirewallPolicyLayer4Config) []string {
	values := make([]string, 0, len(configs))
	for _, config := range configs {
		if config.IPProtocol == "" {
			continue
		}
		if len(config.Ports) == 0 {
			values = append(values, config.IPProtocol)
			continue
		}
		values = append(values, config.IPProtocol+":"+strings.Join(config.Ports, "|"))
	}
	return values
}

func computeFirewallPolicyAssociations(associations []ComputeFirewallPolicyAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		if label := firstNonEmpty(association.DisplayName, association.ShortName, association.Name, lastPathSegment(association.AttachmentTarget)); label != "" {
			values = append(values, label)
		}
	}
	return values
}

func computeAutoHealingHealthChecks(policies []ComputeAutoHealingPolicy) []string {
	values := make([]string, 0, len(policies))
	for _, policy := range policies {
		if policy.HealthCheck != "" {
			values = append(values, policy.HealthCheck)
		}
	}
	return values
}

func firstTemplateNetworkInterface(properties ComputeInstanceTemplateProperties) ComputeNetworkInterface {
	if len(properties.NetworkInterfaces) == 0 {
		return ComputeNetworkInterface{}
	}
	return properties.NetworkInterfaces[0]
}

func computeTemplateServiceAccounts(properties ComputeInstanceTemplateProperties) []string {
	accounts := make([]string, 0, len(properties.ServiceAccounts))
	for _, account := range properties.ServiceAccounts {
		if email := strings.TrimSpace(account.Email); email != "" {
			accounts = append(accounts, email)
		}
	}
	return accounts
}

func computeTemplatePublic(properties ComputeInstanceTemplateProperties) bool {
	for _, networkInterface := range properties.NetworkInterfaces {
		if len(networkInterface.AccessConfigs) != 0 {
			return true
		}
	}
	return false
}

func computeTemplateBootDiskKMS(properties ComputeInstanceTemplateProperties) string {
	for _, disk := range properties.Disks {
		if !disk.Boot {
			continue
		}
		if key := strings.TrimSpace(disk.DiskEncryptionKey.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func computeDistributionZones(policy ComputeInstanceDistribution) []string {
	zones := make([]string, 0, len(policy.Zones))
	for _, zone := range policy.Zones {
		if zone.Zone != "" {
			zones = append(zones, lastPathSegment(zone.Zone))
		}
	}
	return zones
}

func computeBackendServiceExternal(scheme string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(scheme)), "EXTERNAL")
}

func computeBackendServiceBackends(backends []ComputeBackendServiceBackend) ([]string, []string, []string, int) {
	names := make([]string, 0, len(backends))
	urls := make([]string, 0, len(backends))
	modes := make([]string, 0, len(backends))
	failoverCount := 0
	for _, backend := range backends {
		if backend.Group != "" {
			urls = append(urls, backend.Group)
			names = append(names, lastPathSegment(backend.Group))
		}
		if backend.BalancingMode != "" {
			modes = appendUnique(modes, backend.BalancingMode)
		}
		if backend.Failover {
			failoverCount++
		}
	}
	return names, urls, modes, failoverCount
}

func computeAddressExternal(addressType string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(addressType))
	return normalized == "" || normalized == "EXTERNAL"
}

func computeBackendBucketUsedBy(references []ComputeBackendBucketReference) ([]string, []string) {
	names := make([]string, 0, len(references))
	urls := make([]string, 0, len(references))
	for _, usedBy := range references {
		reference := strings.TrimSpace(usedBy.Reference)
		if reference == "" {
			continue
		}
		urls = append(urls, reference)
		names = append(names, lastPathSegment(reference))
	}
	return names, urls
}

func computeBackendBucketNegativeCachingCodes(policies []ComputeBackendBucketNegativeCachingEntry) []string {
	codes := make([]string, 0, len(policies))
	for _, policy := range policies {
		if policy.Code != 0 {
			codes = append(codes, strconv.Itoa(policy.Code))
		}
	}
	sort.Strings(codes)
	return codes
}

func computeHealthCheckProbe(record ComputeHealthCheckRecord) (string, ComputeHealthCheckProbe) {
	switch strings.ToUpper(strings.TrimSpace(record.Type)) {
	case "TCP":
		return "TCP", record.TCPHealthCheck
	case "SSL":
		return "SSL", record.SSLHealthCheck
	case "HTTP":
		return "HTTP", record.HTTPHealthCheck
	case "HTTPS":
		return "HTTPS", record.HTTPSHealthCheck
	case "HTTP2":
		return "HTTP2", record.HTTP2HealthCheck
	case "GRPC":
		return "GRPC", record.GRPCHealthCheck
	case "GRPC_TLS":
		return "GRPC_TLS", record.GRPCTLSHealthCheck
	}
	switch {
	case computeHealthCheckProbeConfigured(record.TCPHealthCheck):
		return "TCP", record.TCPHealthCheck
	case computeHealthCheckProbeConfigured(record.SSLHealthCheck):
		return "SSL", record.SSLHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTPHealthCheck):
		return "HTTP", record.HTTPHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTPSHealthCheck):
		return "HTTPS", record.HTTPSHealthCheck
	case computeHealthCheckProbeConfigured(record.HTTP2HealthCheck):
		return "HTTP2", record.HTTP2HealthCheck
	case computeHealthCheckProbeConfigured(record.GRPCHealthCheck):
		return "GRPC", record.GRPCHealthCheck
	case computeHealthCheckProbeConfigured(record.GRPCTLSHealthCheck):
		return "GRPC_TLS", record.GRPCTLSHealthCheck
	default:
		return record.Type, ComputeHealthCheckProbe{}
	}
}

func computeHealthCheckProbeConfigured(probe ComputeHealthCheckProbe) bool {
	return probe.Port != 0 || probe.PortName != "" || probe.PortSpecification != "" || probe.Request != "" || probe.Response != "" || probe.ProxyHeader != "" || probe.Host != "" || probe.RequestPath != "" || probe.GRPCServiceName != ""
}

type computeSecurityPolicyRuleSummary struct {
	actions               []string
	versionedExpressions  []string
	sourceIPRanges        []string
	customExpressions     []string
	defaultAction         string
	previewCount          int
	allowCount            int
	denyCount             int
	throttleCount         int
	rateBasedBanCount     int
	redirectCount         int
	customExpressionCount int
}

func computeSecurityPolicyRules(rules []ComputeSecurityPolicyRule) computeSecurityPolicyRuleSummary {
	summary := computeSecurityPolicyRuleSummary{}
	defaultPriority := -1
	for _, rule := range rules {
		action := strings.TrimSpace(rule.Action)
		normalizedAction := strings.ToLower(action)
		if action != "" {
			summary.actions = appendUnique(summary.actions, action)
		}
		switch {
		case normalizedAction == "allow":
			summary.allowCount++
		case strings.HasPrefix(normalizedAction, "deny"):
			summary.denyCount++
		case strings.HasPrefix(normalizedAction, "throttle"):
			summary.throttleCount++
		case strings.HasPrefix(normalizedAction, "rate_based_ban"):
			summary.rateBasedBanCount++
		case strings.HasPrefix(normalizedAction, "redirect"):
			summary.redirectCount++
		}
		if rule.Preview {
			summary.previewCount++
		}
		if rule.Priority > defaultPriority {
			defaultPriority = rule.Priority
			summary.defaultAction = action
		}
		if versionedExpression := strings.TrimSpace(rule.Match.VersionedExpr); versionedExpression != "" {
			summary.versionedExpressions = appendUnique(summary.versionedExpressions, versionedExpression)
		}
		for _, sourceIPRange := range rule.Match.Config.SrcIPRanges {
			if sourceIPRange = strings.TrimSpace(sourceIPRange); sourceIPRange != "" {
				summary.sourceIPRanges = appendUnique(summary.sourceIPRanges, sourceIPRange)
			}
		}
		if expression := strings.TrimSpace(rule.Match.Expr.Expression); expression != "" {
			summary.customExpressions = append(summary.customExpressions, expression)
			summary.customExpressionCount++
		}
	}
	return summary
}

func computeSecurityPolicyAssociations(associations []ComputeSecurityPolicyAssociation) ([]string, []string) {
	names := make([]string, 0, len(associations))
	urls := make([]string, 0, len(associations))
	for _, association := range associations {
		if association.AttachmentID != "" {
			urls = append(urls, association.AttachmentID)
			names = append(names, firstNonEmpty(association.Name, lastPathSegment(association.AttachmentID)))
			continue
		}
		if association.Name != "" {
			names = append(names, association.Name)
		}
	}
	return names, urls
}

type computeURLMapRouteSummary struct {
	hosts                        []string
	pathMatchers                 []string
	paths                        []string
	backendNames                 []string
	backendURLs                  []string
	pathRulesCount               int
	routeRulesCount              int
	redirectRulesCount           int
	weightedBackendServicesCount int
}

func computeURLMapRoutes(record ComputeURLMapRecord) computeURLMapRouteSummary {
	summary := computeURLMapRouteSummary{}
	addURLMapBackend(&summary, record.DefaultService)
	addURLMapWeightedBackends(&summary, record.DefaultRouteAction)
	if computeURLRedirectConfigured(record.DefaultURLRedirect) {
		summary.redirectRulesCount++
	}
	for _, hostRule := range record.HostRules {
		for _, host := range hostRule.Hosts {
			summary.hosts = appendUnique(summary.hosts, host)
		}
		if hostRule.PathMatcher != "" {
			summary.pathMatchers = appendUnique(summary.pathMatchers, hostRule.PathMatcher)
		}
	}
	for _, matcher := range record.PathMatchers {
		if matcher.Name != "" {
			summary.pathMatchers = appendUnique(summary.pathMatchers, matcher.Name)
		}
		addURLMapBackend(&summary, matcher.DefaultService)
		addURLMapWeightedBackends(&summary, matcher.DefaultRouteAction)
		if computeURLRedirectConfigured(matcher.DefaultURLRedirect) {
			summary.redirectRulesCount++
		}
		for _, rule := range matcher.PathRules {
			summary.pathRulesCount++
			for _, path := range rule.Paths {
				summary.paths = appendUnique(summary.paths, path)
			}
			addURLMapBackend(&summary, rule.Service)
			addURLMapWeightedBackends(&summary, rule.RouteAction)
			if computeURLRedirectConfigured(rule.URLRedirect) {
				summary.redirectRulesCount++
			}
		}
		for _, rule := range matcher.RouteRules {
			summary.routeRulesCount++
			addURLMapBackend(&summary, rule.Service)
			addURLMapWeightedBackends(&summary, rule.RouteAction)
			if computeURLRedirectConfigured(rule.URLRedirect) {
				summary.redirectRulesCount++
			}
		}
	}
	return summary
}

func addURLMapBackend(summary *computeURLMapRouteSummary, backend string) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return
	}
	summary.backendURLs = appendUnique(summary.backendURLs, backend)
	summary.backendNames = appendUnique(summary.backendNames, lastPathSegment(backend))
}

func addURLMapWeightedBackends(summary *computeURLMapRouteSummary, action ComputeURLMapRouteAction) {
	for _, backend := range action.WeightedBackendServices {
		addURLMapBackend(summary, backend.BackendService)
		summary.weightedBackendServicesCount++
	}
}

func computeURLRedirectConfigured(redirect ComputeURLMapURLRedirect) bool {
	return redirect.HostRedirect != "" || redirect.PathRedirect != "" || redirect.PrefixRedirect != "" || redirect.RedirectResponseCode != "" || redirect.HTTPSRedirect || redirect.StripQuery
}

func computeSSLCertificateType(record ComputeSSLCertificateRecord) string {
	switch {
	case len(record.Managed.Domains) != 0 || record.Managed.Status != "" || len(record.Managed.DomainStatus) != 0:
		return "MANAGED"
	case record.SelfManaged.Certificate != "":
		return "SELF_MANAGED"
	default:
		return ""
	}
}

func computeSSLCertificateDomainStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	domains := make([]string, 0, len(statuses))
	for domain := range statuses {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	values := make([]string, 0, len(domains))
	for _, domain := range domains {
		values = append(values, domain+"="+statuses[domain])
	}
	return values
}

func lastPathSegments(values []string) []string {
	segments := make([]string, 0, len(values))
	for _, value := range values {
		if segment := lastPathSegment(value); segment != "" {
			segments = append(segments, segment)
		}
	}
	return segments
}

func computeForwardingRuleTarget(record ComputeForwardingRuleRecord) (string, string, string) {
	if record.BackendService != "" {
		return "backend_service", record.BackendService, lastPathSegment(record.BackendService)
	}
	if record.Target != "" {
		return computeForwardingRuleTargetType(record.Target), record.Target, lastPathSegment(record.Target)
	}
	return "", "", ""
}

func computeForwardingRuleTargetType(targetURL string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(targetURL), "/"), "/")
	if len(parts) < 2 {
		return "target"
	}
	switch parts[len(parts)-2] {
	case "backendServices":
		return "backend_service"
	case "serviceAttachments":
		return "service_attachment"
	case "targetGrpcProxies":
		return "target_grpc_proxy"
	case "targetHttpProxies":
		return "target_http_proxy"
	case "targetHttpsProxies":
		return "target_https_proxy"
	case "targetInstances":
		return "target_instance"
	case "targetPools":
		return "target_pool"
	case "targetSslProxies":
		return "target_ssl_proxy"
	case "targetTcpProxies":
		return "target_tcp_proxy"
	case "targetVpnGateways":
		return "target_vpn_gateway"
	}
	return "target"
}

func computeForwardingRuleExternal(scheme string) bool {
	upper := strings.ToUpper(strings.TrimSpace(scheme))
	return strings.HasPrefix(upper, "EXTERNAL")
}

func computeFirewallPrimaryAllowed(record ComputeFirewallRecord) ComputeFirewallAllowed {
	if len(record.Allowed) == 0 {
		return ComputeFirewallAllowed{IPProtocol: "all"}
	}
	allowed := record.Allowed[0]
	if len(allowed.Ports) == 0 {
		allowed.Ports = []string{"all"}
	}
	return allowed
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

func certificateManagerCertificateType(record CertificateManagerCertificateRecord) string {
	switch {
	case certificateManagerManagedIdentityConfigured(record.ManagedIdentity):
		return "MANAGED_IDENTITY"
	case len(record.Managed.Domains) != 0 || len(record.Managed.DNSAuthorizations) != 0 || record.Managed.State != "":
		return "MANAGED"
	case record.SelfManaged.PEMCertificate != "":
		return "SELF_MANAGED"
	default:
		return ""
	}
}

func certificateManagerManagedIdentityConfigured(identity CertificateManagerManagedIdentityCertificate) bool {
	return strings.TrimSpace(identity.Identity) != "" ||
		strings.TrimSpace(identity.State) != "" ||
		strings.TrimSpace(identity.ProvisioningIssue.Reason) != "" ||
		strings.TrimSpace(identity.ProvisioningIssue.Details) != ""
}

func certificateManagerUsedByNames(usedBy []CertificateManagerUsedBy) []string {
	names := make([]string, 0, len(usedBy))
	for _, usage := range usedBy {
		if strings.TrimSpace(usage.Name) != "" {
			names = append(names, usage.Name)
		}
	}
	return names
}

func certificateManagerAuthorizationAttemptSummary(attempts []CertificateManagerAuthorizationAttemptInfo) ([]string, []string, []string) {
	domains := make([]string, 0, len(attempts))
	states := make([]string, 0, len(attempts))
	failures := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		domains = appendUnique(domains, attempt.Domain)
		states = appendUnique(states, attempt.State)
		failures = appendUnique(failures, attempt.FailureReason)
	}
	return domains, states, failures
}

func certificateManagerGCLBTargets(targets []CertificateManagerGCLBTarget) ([]string, []string, []string, []string) {
	httpsProxies := make([]string, 0, len(targets))
	sslProxies := make([]string, 0, len(targets))
	ipAddresses := make([]string, 0)
	ports := make([]string, 0)
	for _, target := range targets {
		httpsProxies = appendUnique(httpsProxies, target.TargetHTTPSProxy)
		sslProxies = appendUnique(sslProxies, target.TargetSSLProxy)
		for _, config := range target.IPConfigs {
			ipAddresses = appendUnique(ipAddresses, config.IPAddress)
			for _, port := range config.Ports {
				if port > 0 {
					ports = appendUnique(ports, strconv.Itoa(port))
				}
			}
		}
	}
	return httpsProxies, sslProxies, ipAddresses, ports
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

func monitoringAlertConditionSummary(conditions []MonitoringAlertPolicyCondition) ([]string, []string) {
	names := make([]string, 0, len(conditions))
	typeSeen := map[string]struct{}{}
	for _, condition := range conditions {
		if name := firstNonEmpty(condition.DisplayName, lastPathSegment(condition.Name)); name != "" {
			names = append(names, name)
		}
		for _, conditionType := range []struct {
			name string
			raw  json.RawMessage
		}{
			{name: "threshold", raw: condition.ConditionThreshold},
			{name: "absent", raw: condition.ConditionAbsent},
			{name: "mql", raw: condition.ConditionMonitoringQueryLanguage},
			{name: "promql", raw: condition.ConditionPrometheusQueryLanguage},
			{name: "matched_log", raw: condition.ConditionMatchedLog},
			{name: "sql", raw: condition.ConditionSQL},
		} {
			if len(conditionType.raw) != 0 {
				typeSeen[conditionType.name] = struct{}{}
			}
		}
	}
	types := make([]string, 0, len(typeSeen))
	for conditionType := range typeSeen {
		types = append(types, conditionType)
	}
	sort.Strings(types)
	return names, types
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

func parentResourceName(name string, childCollection string) string {
	marker := "/" + strings.Trim(childCollection, "/") + "/"
	if index := strings.LastIndex(name, marker); index > 0 {
		return name[:index]
	}
	return ""
}

func firstSpannerEncryptionType(values []SpannerEncryptionInfo) string {
	for _, value := range values {
		if strings.TrimSpace(value.EncryptionType) != "" {
			return value.EncryptionType
		}
	}
	return ""
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

func PayloadWithRaw(raw json.RawMessage, values PayloadValues) ([]byte, error) {
	return payloadWithRaw(raw, values)
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

func LabelLookup(labels map[string]string, keys ...string) string {
	return labelLookup(labels, keys...)
}

func normalizeLabelKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func CriticalityFromLabels(labels map[string]string) string {
	for _, value := range labels {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "critical", "high", "tier0", "tier_0", "tier-0", "crown_jewel", "crown-jewel":
			return "critical"
		}
	}
	return ""
}

func CrownJewelFromLabels(labels map[string]string) bool {
	for _, key := range []string{"crown_jewel", "crown-jewel", "tier0", "tier_0", "business_critical"} {
		if value := strings.ToLower(labelLookup(labels, key)); value == "true" || value == "yes" || value == "1" || value == "critical" {
			return true
		}
	}
	return strings.EqualFold(CriticalityFromLabels(labels), "critical")
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

func LocationFromResourceName(value string) string {
	return locationFromResourceName(value)
}

func lastPathSegment(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func LastPathSegment(value string) string {
	return lastPathSegment(value)
}

func EscapePathSegments(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
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

func TrimEmptyAttributes(attributes map[string]string) {
	trimEmptyAttributes(attributes)
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}

func SanitizeEventID(value string) string {
	return sanitizeEventID(value)
}

func SanitizeURNPart(value string) string {
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return strings.Trim(value, "_")
}
