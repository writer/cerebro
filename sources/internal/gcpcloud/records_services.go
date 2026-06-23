package gcpcloud

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
)

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

type CloudSQLDatabaseRecord struct {
	Name           string          `json:"name"`
	Instance       string          `json:"instance"`
	Project        string          `json:"project"`
	SelfLink       string          `json:"selfLink"`
	Charset        string          `json:"charset"`
	Collation      string          `json:"collation"`
	Etag           string          `json:"etag"`
	InstanceName   string          `json:"-"`
	InstanceRegion string          `json:"-"`
	Raw            json.RawMessage `json:"-"`
}

type CloudSQLUserRecord struct {
	Name           string          `json:"name"`
	Host           string          `json:"host"`
	Instance       string          `json:"instance"`
	Project        string          `json:"project"`
	Type           string          `json:"type"`
	Etag           string          `json:"etag"`
	PasswordPolicy json.RawMessage `json:"passwordPolicy"`
	InstanceName   string          `json:"-"`
	InstanceRegion string          `json:"-"`
	Raw            json.RawMessage `json:"-"`
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
	Name               string                     `json:"name"`
	Type               string                     `json:"type"`
	DisplayName        string                     `json:"displayName"`
	Description        string                     `json:"description"`
	Labels             map[string]string          `json:"labels"`
	UserLabels         map[string]string          `json:"userLabels"`
	Enabled            *bool                      `json:"enabled"`
	VerificationStatus string                     `json:"verificationStatus"`
	SensitiveLabels    json.RawMessage            `json:"sensitiveLabels"`
	CreationRecord     MonitoringMutationRecord   `json:"creationRecord"`
	MutationRecords    []MonitoringMutationRecord `json:"mutationRecords"`
	Raw                json.RawMessage            `json:"-"`
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

type BigQueryTableRecord struct {
	ID                      string                   `json:"id"`
	SelfLink                string                   `json:"selfLink"`
	TableReference          BigQueryTableReference   `json:"tableReference"`
	FriendlyName            string                   `json:"friendlyName"`
	Description             string                   `json:"description"`
	Type                    string                   `json:"type"`
	Labels                  map[string]string        `json:"labels"`
	Schema                  json.RawMessage          `json:"schema"`
	TimePartitioning        BigQueryTimePartitioning `json:"timePartitioning"`
	RangePartitioning       json.RawMessage          `json:"rangePartitioning"`
	Clustering              BigQueryClustering       `json:"clustering"`
	EncryptionConfiguration BigQueryEncryptionConfig `json:"encryptionConfiguration"`
	CreationTime            string                   `json:"creationTime"`
	ExpirationTime          string                   `json:"expirationTime"`
	LastModifiedTime        string                   `json:"lastModifiedTime"`
	NumBytes                string                   `json:"numBytes"`
	NumLongTermBytes        string                   `json:"numLongTermBytes"`
	NumRows                 string                   `json:"numRows"`
	ExternalDataConfig      json.RawMessage          `json:"externalDataConfiguration"`
	StreamingBuffer         json.RawMessage          `json:"streamingBuffer"`
	View                    json.RawMessage          `json:"view"`
	DatasetID               string                   `json:"-"`
	DatasetLocation         string                   `json:"-"`
	Raw                     json.RawMessage          `json:"-"`
}

type BigQueryTableReference struct {
	ProjectID string `json:"projectId"`
	DatasetID string `json:"datasetId"`
	TableID   string `json:"tableId"`
}

type BigQueryTimePartitioning struct {
	Type          string `json:"type"`
	Field         string `json:"field"`
	ExpirationMS  string `json:"expirationMs"`
	RequireFilter bool   `json:"requirePartitionFilter"`
}

type BigQueryClustering struct {
	Fields []string `json:"fields"`
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

func CloudSQLDatabaseResourceID(projectID string, record CloudSQLDatabaseRecord) string {
	if strings.TrimSpace(record.SelfLink) != "" {
		return strings.TrimSpace(record.SelfLink)
	}
	project := firstNonEmpty(record.Project, projectID)
	instance := firstNonEmpty(record.Instance, record.InstanceName)
	return strings.Trim(strings.Join([]string{project, "instances", instance, "databases", record.Name}, "/"), "/")
}

func CloudSQLDatabaseEvent(settings Settings, record CloudSQLDatabaseRecord) (*primitives.Event, error) {
	resourceID := CloudSQLDatabaseResourceID(settings.ProjectID, record)
	instanceName := firstNonEmpty(record.Instance, record.InstanceName)
	attributes := cloudResourceAttributes(settings, "cloud_sql_database", resourceID, record.Name, "cloud_sql_database", record.InstanceRegion, nil)
	attributes["project_id"] = firstNonEmpty(record.Project, settings.ProjectID)
	attributes["instance_name"] = instanceName
	attributes["database_name"] = record.Name
	attributes["charset"] = record.Charset
	attributes["collation"] = record.Collation
	attributes["etag"] = record.Etag
	payload, err := payloadWithRaw(record.Raw, map[string]any{"instance_name": instanceName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-sql-database-"+resourceID, "gcp.cloud_sql_database", "gcp/cloud_sql_database/v1", payload, attributes)
}

func CloudSQLUserResourceID(projectID string, record CloudSQLUserRecord) string {
	project := firstNonEmpty(record.Project, projectID)
	instance := firstNonEmpty(record.Instance, record.InstanceName)
	parts := []string{project, "instances", instance, "users", record.Name}
	if strings.TrimSpace(record.Host) != "" {
		parts = append(parts, "hosts", record.Host)
	}
	return strings.Trim(strings.Join(parts, "/"), "/")
}

func CloudSQLUserEvent(settings Settings, record CloudSQLUserRecord) (*primitives.Event, error) {
	resourceID := CloudSQLUserResourceID(settings.ProjectID, record)
	instanceName := firstNonEmpty(record.Instance, record.InstanceName)
	attributes := cloudResourceAttributes(settings, "cloud_sql_user", resourceID, record.Name, "cloud_sql_user", record.InstanceRegion, nil)
	attributes["project_id"] = firstNonEmpty(record.Project, settings.ProjectID)
	attributes["instance_name"] = instanceName
	attributes["user_name"] = record.Name
	attributes["host"] = record.Host
	attributes["user_type"] = record.Type
	attributes["type"] = record.Type
	attributes["etag"] = record.Etag
	attributes["password_policy_configured"] = boolString(len(record.PasswordPolicy) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"instance_name": instanceName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-sql-user-"+resourceID, "gcp.cloud_sql_user", "gcp/cloud_sql_user/v1", payload, attributes)
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
	mutationRecord := latestMonitoringMutationRecord(record.MutationRecords)
	attributes := cloudResourceAttributes(settings, "monitoring_notification_channel", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "monitoring_notification_channel", "global", labels)
	attributes["display_name"] = record.DisplayName
	attributes["description"] = record.Description
	attributes["channel_type"] = record.Type
	attributes["verification_status"] = record.VerificationStatus
	attributes["sensitive_labels_present"] = boolString(len(record.SensitiveLabels) != 0)
	attributes["created_at"] = record.CreationRecord.MutateTime
	attributes["created_by"] = record.CreationRecord.MutatedBy
	attributes["updated_at"] = mutationRecord.MutateTime
	attributes["updated_by"] = mutationRecord.MutatedBy
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

func latestMonitoringMutationRecord(records []MonitoringMutationRecord) MonitoringMutationRecord {
	if len(records) == 0 {
		return MonitoringMutationRecord{}
	}
	latest := records[0]
	for _, record := range records[1:] {
		if monitoringMutationAfter(record, latest) {
			latest = record
		}
	}
	return latest
}

func monitoringMutationAfter(candidate, current MonitoringMutationRecord) bool {
	candidateTime, candidateErr := time.Parse(time.RFC3339Nano, candidate.MutateTime)
	currentTime, currentErr := time.Parse(time.RFC3339Nano, current.MutateTime)
	if candidateErr == nil && currentErr == nil {
		return candidateTime.After(currentTime)
	}
	return candidate.MutateTime > current.MutateTime
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

func BigQueryTableResourceID(projectID string, record BigQueryTableRecord) string {
	if strings.TrimSpace(record.ID) != "" {
		return strings.TrimSpace(record.ID)
	}
	datasetID := firstNonEmpty(record.TableReference.DatasetID, record.DatasetID)
	tableID := record.TableReference.TableID
	if datasetID != "" && tableID != "" {
		return strings.TrimSpace(projectID) + ":" + datasetID + "." + tableID
	}
	return tableID
}

func BigQueryTableEvent(settings Settings, record BigQueryTableRecord) (*primitives.Event, error) {
	resourceID := BigQueryTableResourceID(settings.ProjectID, record)
	datasetID := firstNonEmpty(record.TableReference.DatasetID, record.DatasetID)
	tableID := firstNonEmpty(record.TableReference.TableID, lastPathSegment(resourceID))
	attributes := cloudResourceAttributes(settings, "bigquery_table", resourceID, tableID, "bigquery_table", record.DatasetLocation, record.Labels)
	attributes["dataset_id"] = datasetID
	attributes["table_id"] = tableID
	attributes["friendly_name"] = record.FriendlyName
	attributes["description"] = record.Description
	attributes["self_link"] = record.SelfLink
	attributes["table_type"] = record.Type
	attributes["type"] = record.Type
	attributes["kms_key_name"] = record.EncryptionConfiguration.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.EncryptionConfiguration.KMSKeyName != "")
	attributes["partitioned"] = boolString(record.TimePartitioning.Type != "" || len(record.RangePartitioning) != 0)
	attributes["time_partitioning_type"] = record.TimePartitioning.Type
	attributes["time_partitioning_field"] = record.TimePartitioning.Field
	attributes["require_partition_filter"] = boolString(record.TimePartitioning.RequireFilter)
	attributes["partition_expiration_ms"] = record.TimePartitioning.ExpirationMS
	attributes["range_partitioned"] = boolString(len(record.RangePartitioning) != 0)
	attributes["clustered"] = boolString(len(record.Clustering.Fields) != 0)
	attributes["clustering_fields"] = strings.Join(record.Clustering.Fields, ",")
	attributes["schema_configured"] = boolString(len(record.Schema) != 0)
	attributes["external_data_configured"] = boolString(len(record.ExternalDataConfig) != 0)
	attributes["streaming_buffer_present"] = boolString(len(record.StreamingBuffer) != 0)
	attributes["view_configured"] = boolString(len(record.View) != 0)
	attributes["created_at"] = unixMillisTime(record.CreationTime)
	attributes["updated_at"] = unixMillisTime(record.LastModifiedTime)
	attributes["expiration_time"] = unixMillisTime(record.ExpirationTime)
	attributes["num_bytes"] = record.NumBytes
	attributes["num_long_term_bytes"] = record.NumLongTermBytes
	attributes["num_rows"] = record.NumRows
	payload, err := payloadWithRaw(record.Raw, map[string]any{"dataset_id": datasetID, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-bigquery-table-"+resourceID, "gcp.bigquery_table", "gcp/bigquery_table/v1", payload, attributes)
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

func serviceUsageNames(services []ServiceUsageServiceRecord) []string {
	names := make([]string, 0, len(services))
	for _, service := range services {
		name := firstNonEmpty(service.Config.Name, lastPathSegment(service.Name), service.Name)
		names = appendUnique(names, name)
	}
	return names
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

func firstSpannerEncryptionType(values []SpannerEncryptionInfo) string {
	for _, value := range values {
		if strings.TrimSpace(value.EncryptionType) != "" {
			return value.EncryptionType
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
