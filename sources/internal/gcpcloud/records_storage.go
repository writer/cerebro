package gcpcloud

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

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

type SecretVersionRecord struct {
	Name                           string          `json:"name"`
	State                          string          `json:"state"`
	CreateTime                     string          `json:"createTime"`
	DestroyTime                    string          `json:"destroyTime"`
	ScheduledDestroyTime           string          `json:"scheduledDestroyTime"`
	Etag                           string          `json:"etag"`
	ClientSpecifiedPayloadChecksum bool            `json:"clientSpecifiedPayloadChecksum"`
	ReplicationStatus              json.RawMessage `json:"replicationStatus"`
	SecretName                     string          `json:"-"`
	SecretLocation                 string          `json:"-"`
	Raw                            json.RawMessage `json:"-"`
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

func SecretVersionEvent(settings Settings, record SecretVersionRecord) (*primitives.Event, error) {
	secretName := firstNonEmpty(record.SecretName, parentResourceName(record.Name, "versions"))
	versionID := lastPathSegment(record.Name)
	attributes := cloudResourceAttributes(settings, "secret_manager_version", record.Name, versionID, "secret_manager_version", record.SecretLocation, nil)
	attributes["secret_name"] = lastPathSegment(secretName)
	attributes["secret_url"] = secretName
	attributes["version_id"] = versionID
	attributes["state"] = record.State
	attributes["status"] = record.State
	attributes["enabled"] = boolString(strings.EqualFold(record.State, "ENABLED"))
	attributes["disabled"] = boolString(strings.EqualFold(record.State, "DISABLED"))
	attributes["destroyed"] = boolString(strings.EqualFold(record.State, "DESTROYED"))
	attributes["create_time"] = record.CreateTime
	attributes["destroy_time"] = record.DestroyTime
	attributes["scheduled_destroy_time"] = record.ScheduledDestroyTime
	attributes["etag"] = record.Etag
	attributes["client_specified_payload_checksum"] = boolString(record.ClientSpecifiedPayloadChecksum)
	attributes["replication_status_present"] = boolString(len(record.ReplicationStatus) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "secret_name": secretName})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-secret-manager-version-"+record.Name, "gcp.secret_manager_version", "gcp/secret_manager_version/v1", payload, attributes)
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

func SecretLocation(record SecretRecord) string {
	return secretLocation(record)
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
