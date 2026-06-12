package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/smithy-go"

	"github.com/writer/cerebro/internal/primitives"
)

type secretsmanagertypesSecret = secretsmanagertypes.SecretListEntry

type awsS3Bucket struct {
	Bucket            s3types.Bucket
	Name              string
	ARN               string
	Region            string
	Tags              map[string]string
	Encryption        string
	KMSKeyID          string
	BucketKeyEnabled  bool
	Versioning        string
	LoggingEnabled    bool
	PublicAccessBlock *s3types.PublicAccessBlockConfiguration
}

type awsRDSInstance struct {
	Instance rdstypes.DBInstance
	Tags     map[string]string
}

type awsKMSKey struct {
	Metadata        kmstypes.KeyMetadata
	Tags            map[string]string
	RotationEnabled *bool
}

type awsSQSQueue struct {
	URL        string
	ARN        string
	Name       string
	Attributes map[string]string
	Tags       map[string]string
}

type awsSNSTopic struct {
	ARN        string
	Name       string
	Attributes map[string]string
	Tags       map[string]string
}

type awsECRRepository struct {
	Repository ecrtypes.Repository
	Tags       map[string]string
}

func listS3Buckets(ctx context.Context, clients awsClients, settings settings, _ string, _ int) ([]awsS3Bucket, string, error) {
	out, err := clients.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsS3Bucket, 0, len(out.Buckets))
	for _, bucket := range out.Buckets {
		name := awssdk.ToString(bucket.Name)
		if name == "" {
			continue
		}
		record := awsS3Bucket{
			Bucket: bucket,
			Name:   name,
			ARN:    firstNonEmpty(awssdk.ToString(bucket.BucketArn), s3BucketARN(name)),
			Region: firstNonEmpty(awssdk.ToString(bucket.BucketRegion), settings.region),
		}
		if location, err := clients.s3.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: awssdk.String(name)}); err == nil {
			record.Region = firstNonEmpty(s3BucketLocationRegion(location.LocationConstraint), record.Region)
		} else if !optionalAWSError(err, "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket location %q: %w", name, err)
		}
		bucketS3 := s3ClientForRegion(clients, record.Region)
		if tags, err := bucketS3.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: awssdk.String(name)}); err == nil {
			record.Tags = s3TagMap(tags.TagSet)
		} else if !optionalAWSError(err, "NoSuchTagSet", "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket tags %q: %w", name, err)
		}
		if encryption, err := bucketS3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: awssdk.String(name)}); err == nil {
			record.Encryption, record.KMSKeyID, record.BucketKeyEnabled = s3EncryptionSummary(encryption.ServerSideEncryptionConfiguration)
		} else if !optionalAWSError(err, "ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket encryption %q: %w", name, err)
		}
		if versioning, err := bucketS3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: awssdk.String(name)}); err == nil {
			record.Versioning = string(versioning.Status)
		} else if !optionalAWSError(err, "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket versioning %q: %w", name, err)
		}
		if logging, err := bucketS3.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: awssdk.String(name)}); err == nil {
			record.LoggingEnabled = logging.LoggingEnabled != nil
		} else if !optionalAWSError(err, "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket logging %q: %w", name, err)
		}
		if block, err := bucketS3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: awssdk.String(name)}); err == nil {
			record.PublicAccessBlock = block.PublicAccessBlockConfiguration
		} else if !optionalAWSError(err, "NoSuchPublicAccessBlockConfiguration", "NoSuchBucket") {
			return nil, "", fmt.Errorf("get bucket public access block %q: %w", name, err)
		}
		records = append(records, record)
	}
	return records, "", nil
}

func listRDSInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsRDSInstance, string, error) {
	out, err := clients.rds.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		Marker:     stringPtr(cursor),
		MaxRecords: awssdk.Int32(boundedAWSPageSizeInt32(limit, 20, 100)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsRDSInstance, 0, len(out.DBInstances))
	for _, instance := range out.DBInstances {
		records = append(records, awsRDSInstance{Instance: instance, Tags: rdsTagMap(instance.TagList)})
	}
	return records, awssdk.ToString(out.Marker), nil
}

func listKMSKeys(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsKMSKey, string, error) {
	out, err := clients.kms.ListKeys(ctx, &kms.ListKeysInput{
		Marker: stringPtr(cursor),
		Limit:  awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsKMSKey, 0, len(out.Keys))
	for _, summary := range out.Keys {
		keyID := awssdk.ToString(summary.KeyId)
		if keyID == "" {
			continue
		}
		describe, err := clients.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: awssdk.String(keyID)})
		if err != nil && !optionalAWSError(err, "AccessDeniedException", "NotFoundException", "KMSInvalidStateException") {
			return nil, "", fmt.Errorf("describe kms key %q: %w", keyID, err)
		}
		if err != nil || describe.KeyMetadata == nil {
			continue
		}
		record := awsKMSKey{Metadata: *describe.KeyMetadata}
		if tags, err := clients.kms.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: awssdk.String(keyID), Limit: awssdk.Int32(50)}); err == nil {
			record.Tags = kmsTagMap(tags.Tags)
		} else if !optionalAWSError(err, "AccessDeniedException", "NotFoundException") {
			return nil, "", fmt.Errorf("list kms tags %q: %w", keyID, err)
		}
		if rotation, err := clients.kms.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: awssdk.String(keyID)}); err == nil {
			record.RotationEnabled = &rotation.KeyRotationEnabled
		} else if !optionalAWSError(err, "AccessDeniedException", "UnsupportedOperationException", "KMSInvalidStateException", "NotFoundException") {
			return nil, "", fmt.Errorf("get kms rotation %q: %w", keyID, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextMarker), nil
}

func listSecrets(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]secretsmanagertypesSecret, string, error) {
	out, err := clients.secrets.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 100)),
	})
	if err != nil {
		return nil, "", err
	}
	return out.SecretList, awssdk.ToString(out.NextToken), nil
}

func listSQSQueues(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSQSQueue, string, error) {
	out, err := clients.sqs.ListQueues(ctx, &sqs.ListQueuesInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSQSQueue, 0, len(out.QueueUrls))
	for _, queueURL := range out.QueueUrls {
		record := awsSQSQueue{URL: queueURL, Name: sqsQueueName(queueURL)}
		attributes, err := clients.sqs.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       awssdk.String(queueURL),
			AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll},
		})
		if err != nil {
			return nil, "", fmt.Errorf("get sqs queue attributes %q: %w", queueURL, err)
		}
		record.Attributes = attributes.Attributes
		record.ARN = firstNonEmpty(attributes.Attributes["QueueArn"], record.URL)
		if tags, err := clients.sqs.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: awssdk.String(queueURL)}); err == nil {
			record.Tags = tags.Tags
		} else if !optionalAWSError(err, "QueueDoesNotExist") {
			return nil, "", fmt.Errorf("list sqs queue tags %q: %w", queueURL, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSNSTopics(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSNSTopic, string, error) {
	out, err := clients.sns.ListTopics(ctx, &sns.ListTopicsInput{
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSNSTopic, 0, len(out.Topics))
	for _, topic := range out.Topics {
		arn := awssdk.ToString(topic.TopicArn)
		if arn == "" {
			continue
		}
		record := awsSNSTopic{ARN: arn, Name: awsResourceName(arn)}
		attributes, err := clients.sns.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("get sns topic attributes %q: %w", arn, err)
		}
		record.Attributes = attributes.Attributes
		if tags, err := clients.sns.ListTagsForResource(ctx, &sns.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = snsTagMap(tags.Tags)
		} else if !optionalAWSError(err, "NotFound") {
			return nil, "", fmt.Errorf("list sns topic tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listECRRepositories(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsECRRepository, string, error) {
	out, err := clients.ecr.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsECRRepository, 0, len(out.Repositories))
	for _, repository := range out.Repositories {
		record := awsECRRepository{Repository: repository}
		if arn := awssdk.ToString(repository.RepositoryArn); arn != "" {
			if tags, err := clients.ecr.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
				record.Tags = ecrTagMap(tags.Tags)
			} else if !optionalAWSError(err, "RepositoryNotFoundException") {
				return nil, "", fmt.Errorf("list ecr repository tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func s3BucketEvent(settings settings, record awsS3Bucket) (*primitives.Event, error) {
	public := s3BucketPublic(record)
	attributes := commonCloudAssetAttributes(settings, record.Region, familyS3Bucket, firstNonEmpty(record.ARN, record.Name), record.Name, "s3_bucket", record.Tags)
	attributes["arn"] = record.ARN
	attributes["bucket_name"] = record.Name
	attributes["encryption"] = record.Encryption
	attributes["kms_key_id"] = record.KMSKeyID
	attributes["bucket_key_enabled"] = boolString(record.BucketKeyEnabled)
	attributes["versioning"] = record.Versioning
	attributes["logging"] = boolString(record.LoggingEnabled)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = boolString(public)
	attributes["block_public_acls"] = boolString(s3PublicBlockBool(record.PublicAccessBlock, "block_public_acls"))
	attributes["block_public_policy"] = boolString(s3PublicBlockBool(record.PublicAccessBlock, "block_public_policy"))
	attributes["ignore_public_acls"] = boolString(s3PublicBlockBool(record.PublicAccessBlock, "ignore_public_acls"))
	attributes["restrict_public_buckets"] = boolString(s3PublicBlockBool(record.PublicAccessBlock, "restrict_public_buckets"))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": record.Region, "bucket": record.Bucket, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-s3-bucket-"+firstNonEmpty(record.ARN, record.Name), "aws.s3_bucket", "aws/s3_bucket/v1", payload, attributes, firstTime(record.Bucket.CreationDate))
}

func rdsInstanceEvent(settings settings, record awsRDSInstance) (*primitives.Event, error) {
	instance := record.Instance
	arn := awssdk.ToString(instance.DBInstanceArn)
	name := awssdk.ToString(instance.DBInstanceIdentifier)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyRDSInstance, firstNonEmpty(arn, name), name, "rds_instance", record.Tags)
	attributes["arn"] = arn
	attributes["db_instance_identifier"] = name
	attributes["engine"] = awssdk.ToString(instance.Engine)
	attributes["engine_version"] = awssdk.ToString(instance.EngineVersion)
	attributes["state"] = awssdk.ToString(instance.DBInstanceStatus)
	attributes["public"] = boolString(awssdk.ToBool(instance.PubliclyAccessible))
	attributes["internet_exposed"] = boolString(awssdk.ToBool(instance.PubliclyAccessible))
	attributes["encryption"] = boolString(awssdk.ToBool(instance.StorageEncrypted))
	attributes["kms_key_id"] = awssdk.ToString(instance.KmsKeyId)
	attributes["deletion_protection"] = boolString(awssdk.ToBool(instance.DeletionProtection))
	attributes["backups"] = boolString(awssdk.ToInt32(instance.BackupRetentionPeriod) > 0)
	attributes["backup_retention_days"] = int32AttrString(instance.BackupRetentionPeriod)
	attributes["multi_az"] = boolString(awssdk.ToBool(instance.MultiAZ))
	attributes["vpc_security_group_ids"] = strings.Join(rdsSecurityGroupIDs(instance.VpcSecurityGroups), ",")
	attributes["cloudwatch_log_exports"] = strings.Join(cleanStrings(instance.EnabledCloudwatchLogsExports), ",")
	if instance.Endpoint != nil {
		attributes["endpoint"] = awssdk.ToString(instance.Endpoint.Address)
		attributes["port"] = int32AttrString(instance.Endpoint.Port)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-rds-instance-"+firstNonEmpty(arn, name), "aws.rds_instance", "aws/rds_instance/v1", payload, attributes, firstTime(instance.InstanceCreateTime))
}

func kmsKeyEvent(settings settings, record awsKMSKey) (*primitives.Event, error) {
	key := record.Metadata
	arn := awssdk.ToString(key.Arn)
	keyID := awssdk.ToString(key.KeyId)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyKMSKey, firstNonEmpty(arn, keyID), keyID, "kms_key", record.Tags)
	attributes["arn"] = arn
	attributes["key_id"] = keyID
	attributes["description"] = awssdk.ToString(key.Description)
	attributes["state"] = string(key.KeyState)
	attributes["enabled"] = boolString(key.Enabled)
	attributes["key_manager"] = string(key.KeyManager)
	attributes["key_spec"] = string(key.KeySpec)
	attributes["key_usage"] = string(key.KeyUsage)
	attributes["origin"] = string(key.Origin)
	attributes["multi_region"] = boolString(awssdk.ToBool(key.MultiRegion))
	if record.RotationEnabled != nil {
		attributes["rotation"] = boolString(*record.RotationEnabled)
	}
	addTimeAttribute(attributes, "deletion_at", key.DeletionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "key": key, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-kms-key-"+firstNonEmpty(arn, keyID), "aws.kms_key", "aws/kms_key/v1", payload, attributes, firstTime(key.CreationDate))
}

func secretEvent(settings settings, secret secretsmanagertypesSecret) (*primitives.Event, error) {
	arn := awssdk.ToString(secret.ARN)
	name := awssdk.ToString(secret.Name)
	tags := secretTagMap(secret.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySecret, firstNonEmpty(arn, name), name, "secret", tags)
	attributes["arn"] = arn
	attributes["secret_name"] = name
	attributes["kms_key_id"] = awssdk.ToString(secret.KmsKeyId)
	attributes["encryption"] = boolString(true)
	attributes["rotation"] = boolString(awssdk.ToBool(secret.RotationEnabled))
	attributes["rotation_lambda_arn"] = awssdk.ToString(secret.RotationLambdaARN)
	attributes["owning_service"] = awssdk.ToString(secret.OwningService)
	attributes["primary_region"] = awssdk.ToString(secret.PrimaryRegion)
	attributes["retention"] = boolString(secret.DeletedDate != nil)
	addTimeAttribute(attributes, "last_accessed_at", secret.LastAccessedDate)
	addTimeAttribute(attributes, "last_changed_at", secret.LastChangedDate)
	addTimeAttribute(attributes, "last_rotated_at", secret.LastRotatedDate)
	addTimeAttribute(attributes, "next_rotation_at", secret.NextRotationDate)
	addTimeAttribute(attributes, "deleted_at", secret.DeletedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "secret": secret})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-secret-"+firstNonEmpty(arn, name), "aws.secret", "aws/secret/v1", payload, attributes, firstTime(secret.CreatedDate))
}

func sqsQueueEvent(settings settings, queue awsSQSQueue) (*primitives.Event, error) {
	attributes := commonCloudAssetAttributes(settings, settings.region, familySQSQueue, firstNonEmpty(queue.ARN, queue.URL, queue.Name), queue.Name, "sqs_queue", queue.Tags)
	attributes["arn"] = queue.ARN
	attributes["queue_url"] = queue.URL
	attributes["queue_name"] = queue.Name
	attributes["encryption"] = boolString(queue.Attributes["KmsMasterKeyId"] != "" || strings.EqualFold(queue.Attributes["SqsManagedSseEnabled"], "true"))
	attributes["kms_key_id"] = queue.Attributes["KmsMasterKeyId"]
	attributes["sqs_managed_sse_enabled"] = queue.Attributes["SqsManagedSseEnabled"]
	attributes["retention_seconds"] = queue.Attributes["MessageRetentionPeriod"]
	attributes["visibility_timeout_seconds"] = queue.Attributes["VisibilityTimeout"]
	attributes["public"] = boolString(policyAllowsWildcardPrincipal(queue.Attributes["Policy"]))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "queue_url": queue.URL, "attributes": queue.Attributes, "tags": queue.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sqs-queue-"+firstNonEmpty(queue.ARN, queue.URL, queue.Name), "aws.sqs_queue", "aws/sqs_queue/v1", payload, attributes, unixAttributeTime(queue.Attributes["CreatedTimestamp"]))
}

func snsTopicEvent(settings settings, topic awsSNSTopic) (*primitives.Event, error) {
	attributes := commonCloudAssetAttributes(settings, settings.region, familySNSTopic, firstNonEmpty(topic.ARN, topic.Name), topic.Name, "sns_topic", topic.Tags)
	attributes["arn"] = topic.ARN
	attributes["topic_arn"] = topic.ARN
	attributes["topic_name"] = topic.Name
	attributes["encryption"] = boolString(topic.Attributes["KmsMasterKeyId"] != "")
	attributes["kms_key_id"] = topic.Attributes["KmsMasterKeyId"]
	attributes["tracing_config"] = topic.Attributes["TracingConfig"]
	attributes["public"] = boolString(policyAllowsWildcardPrincipal(topic.Attributes["Policy"]))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "topic_arn": topic.ARN, "attributes": topic.Attributes, "tags": topic.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sns-topic-"+firstNonEmpty(topic.ARN, topic.Name), "aws.sns_topic", "aws/sns_topic/v1", payload, attributes, time.Now().UTC())
}

func ecrRepositoryEvent(settings settings, record awsECRRepository) (*primitives.Event, error) {
	repository := record.Repository
	arn := awssdk.ToString(repository.RepositoryArn)
	name := awssdk.ToString(repository.RepositoryName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyECRRepository, firstNonEmpty(arn, name), name, "ecr_repository", record.Tags)
	attributes["arn"] = arn
	attributes["repository_arn"] = arn
	attributes["repository_name"] = name
	attributes["repository_uri"] = awssdk.ToString(repository.RepositoryUri)
	attributes["registry_id"] = awssdk.ToString(repository.RegistryId)
	attributes["image_tag_mutability"] = string(repository.ImageTagMutability)
	if repository.EncryptionConfiguration != nil {
		attributes["encryption"] = string(repository.EncryptionConfiguration.EncryptionType)
		attributes["kms_key_id"] = awssdk.ToString(repository.EncryptionConfiguration.KmsKey)
	}
	if repository.ImageScanningConfiguration != nil {
		attributes["scan_on_push"] = boolString(repository.ImageScanningConfiguration.ScanOnPush)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "repository": repository, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ecr-repository-"+firstNonEmpty(arn, name), "aws.ecr_repository", "aws/ecr_repository/v1", payload, attributes, firstTime(repository.CreatedAt))
}

func commonCloudAssetAttributes(settings settings, region string, family string, resourceID string, resourceName string, resourceType string, tags map[string]string) map[string]string {
	env := tagLookup(tags, "environment", "env", "stage")
	return map[string]string{
		"domain":            settings.accountID,
		"env":               env,
		"environment":       env,
		"family":            family,
		"owner":             tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"region":            firstNonEmpty(region, settings.region),
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "aws",
		"resource_type":     resourceType,
		"tags":              encodeAWSTags(tags),
		"team":              tagLookup(tags, "team", "squad", "group"),
	}
}

func s3BucketARN(name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return "arn:aws:s3:::" + strings.TrimSpace(name)
}

func s3ClientForRegion(clients awsClients, region string) awsS3API {
	region = strings.TrimSpace(region)
	if clients.s3ByRegion == nil || region == "" || region == clients.cfg.Region {
		return clients.s3
	}
	return clients.s3ByRegion(region)
}

func s3BucketLocationRegion(value s3types.BucketLocationConstraint) string {
	switch value {
	case "":
		return "us-east-1"
	case s3types.BucketLocationConstraint("EU"):
		return "eu-west-1"
	default:
		return string(value)
	}
}

func s3EncryptionSummary(config *s3types.ServerSideEncryptionConfiguration) (string, string, bool) {
	if config == nil || len(config.Rules) == 0 {
		return "", "", false
	}
	rule := config.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil {
		return "", "", awssdk.ToBool(rule.BucketKeyEnabled)
	}
	defaults := rule.ApplyServerSideEncryptionByDefault
	return string(defaults.SSEAlgorithm), awssdk.ToString(defaults.KMSMasterKeyID), awssdk.ToBool(rule.BucketKeyEnabled)
}

func s3BucketPublic(record awsS3Bucket) bool {
	block := record.PublicAccessBlock
	if block == nil {
		return true
	}
	return !awssdk.ToBool(block.BlockPublicAcls) || !awssdk.ToBool(block.BlockPublicPolicy) || !awssdk.ToBool(block.IgnorePublicAcls) || !awssdk.ToBool(block.RestrictPublicBuckets)
}

func s3PublicBlockBool(block *s3types.PublicAccessBlockConfiguration, field string) bool {
	if block == nil {
		return false
	}
	switch field {
	case "block_public_acls":
		return awssdk.ToBool(block.BlockPublicAcls)
	case "block_public_policy":
		return awssdk.ToBool(block.BlockPublicPolicy)
	case "ignore_public_acls":
		return awssdk.ToBool(block.IgnorePublicAcls)
	case "restrict_public_buckets":
		return awssdk.ToBool(block.RestrictPublicBuckets)
	default:
		return false
	}
}

func s3TagMap(tags []s3types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func rdsTagMap(tags []rdstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func kmsTagMap(tags []kmstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.TagKey)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.TagValue))
		}
	}
	return out
}

func secretTagMap(tags []secretsmanagertypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func snsTagMap(tags []snstypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func ecrTagMap(tags []ecrtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func rdsSecurityGroupIDs(groups []rdstypes.VpcSecurityGroupMembership) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, awssdk.ToString(group.VpcSecurityGroupId))
	}
	return cleanStrings(ids)
}

func sqsQueueName(queueURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(queueURL), "/")
	if trimmed == "" {
		return ""
	}
	if index := strings.LastIndex(trimmed, "/"); index >= 0 && index+1 < len(trimmed) {
		return trimmed[index+1:]
	}
	return trimmed
}

func int32AttrString(value *int32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(int64(*value), 10)
}

func unixAttributeTime(value string) time.Time {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds <= 0 {
		return time.Now().UTC()
	}
	return time.Unix(seconds, 0).UTC()
}

func policyAllowsWildcardPrincipal(policy string) bool {
	var document any
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		normalized := strings.ReplaceAll(strings.ToLower(policy), " ", "")
		return strings.Contains(normalized, `"principal":"*"`) || strings.Contains(normalized, `"aws":"*"`) || strings.Contains(normalized, `"aws":["*"]`)
	}
	return policyPrincipalAllowsWildcard(document)
}

func policyPrincipalAllowsWildcard(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, "Principal") && policyPrincipalValueAllowsWildcard(item) {
				return true
			}
			if policyPrincipalAllowsWildcard(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if policyPrincipalAllowsWildcard(item) {
				return true
			}
		}
	}
	return false
}

func policyPrincipalValueAllowsWildcard(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) == "*"
	case map[string]any:
		for key, item := range typed {
			if (strings.EqualFold(key, "AWS") || strings.EqualFold(key, "CanonicalUser")) && policyPrincipalValueAllowsWildcard(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if policyPrincipalValueAllowsWildcard(item) {
				return true
			}
		}
	}
	return false
}

func optionalAWSError(err error, codes ...string) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && slices.Contains(codes, apiErr.ErrorCode()) {
		return true
	}
	for _, allowed := range codes {
		if strings.Contains(fmt.Sprint(err), allowed) {
			return true
		}
	}
	return false
}
