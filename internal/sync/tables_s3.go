package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

// S3 Bucket Policies
func (e *SyncEngine) s3BucketPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_policies",
		Columns: []string{"arn", "account_id", "region", "bucket", "policy"},
		Fetch:   e.fetchS3BucketPolicies,
	}
}

func (e *SyncEngine) fetchS3BucketPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		policyOut, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_policies", bucketName, bucketRegion, "GetBucketPolicy", err, "NoSuchBucketPolicy")
			continue // No policy
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/policy", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":     arn,
			"arn":        arn,
			"account_id": accountID,
			"region":     bucketRegion,
			"bucket":     bucketName,
			"policy":     aws.ToString(policyOut.Policy),
		})
	}
	return rows, nil
}

// S3 Bucket ACLs / Grants
func (e *SyncEngine) s3BucketGrantTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_grants",
		Columns: []string{"arn", "account_id", "region", "bucket", "grantee_type", "grantee_id", "grantee_uri", "grantee_display_name", "permission"},
		Fetch:   e.fetchS3BucketGrants,
	}
}

func (e *SyncEngine) fetchS3BucketGrants(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		aclOut, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_grants", bucketName, bucketRegion, "GetBucketAcl", err)
			continue
		}

		for i, grant := range aclOut.Grants {
			var granteeType, granteeID, granteeURI, granteeName string
			if grant.Grantee != nil {
				granteeType = string(grant.Grantee.Type)
				granteeID = aws.ToString(grant.Grantee.ID)
				granteeURI = aws.ToString(grant.Grantee.URI)
				granteeName = aws.ToString(grant.Grantee.DisplayName)
			}

			arn := fmt.Sprintf("arn:aws:s3:::%s/acl/%d", bucketName, i)
			rows = append(rows, map[string]interface{}{
				"_cq_id":               arn,
				"arn":                  arn,
				"account_id":           accountID,
				"region":               bucketRegion,
				"bucket":               bucketName,
				"grantee_type":         granteeType,
				"grantee_id":           granteeID,
				"grantee_uri":          granteeURI,
				"grantee_display_name": granteeName,
				"permission":           string(grant.Permission),
			})
		}
	}
	return rows, nil
}

// S3 Bucket Encryption Rules
func (e *SyncEngine) s3BucketEncryptionTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_encryption_rules",
		Columns: []string{"arn", "account_id", "region", "bucket", "sse_algorithm", "kms_master_key_id", "bucket_key_enabled"},
		Fetch:   e.fetchS3BucketEncryption,
	}
}

func (e *SyncEngine) fetchS3BucketEncryption(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		encOut, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_encryption_rules", bucketName, bucketRegion, "GetBucketEncryption", err, "ServerSideEncryptionConfigurationNotFoundError")
			continue // No encryption config
		}

		if encOut.ServerSideEncryptionConfiguration != nil {
			for i, rule := range encOut.ServerSideEncryptionConfiguration.Rules {
				var sseAlgo, kmsKeyID string
				var bucketKeyEnabled bool
				if rule.ApplyServerSideEncryptionByDefault != nil {
					sseAlgo = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
					kmsKeyID = aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
				}
				if rule.BucketKeyEnabled != nil {
					bucketKeyEnabled = *rule.BucketKeyEnabled
				}

				arn := fmt.Sprintf("arn:aws:s3:::%s/encryption/%d", bucketName, i)
				rows = append(rows, map[string]interface{}{
					"_cq_id":             arn,
					"arn":                arn,
					"account_id":         accountID,
					"region":             bucketRegion,
					"bucket":             bucketName,
					"sse_algorithm":      sseAlgo,
					"kms_master_key_id":  kmsKeyID,
					"bucket_key_enabled": bucketKeyEnabled,
				})
			}
		}
	}
	return rows, nil
}

// S3 Bucket Versioning
func (e *SyncEngine) s3BucketVersioningTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_versionings",
		Columns: []string{"arn", "account_id", "region", "bucket", "status", "mfa_delete"},
		Fetch:   e.fetchS3BucketVersioning,
	}
}

func (e *SyncEngine) fetchS3BucketVersioning(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		verOut, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_versionings", bucketName, bucketRegion, "GetBucketVersioning", err)
			continue
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/versioning", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":     arn,
			"arn":        arn,
			"account_id": accountID,
			"region":     bucketRegion,
			"bucket":     bucketName,
			"status":     string(verOut.Status),
			"mfa_delete": string(verOut.MFADelete),
		})
	}
	return rows, nil
}

// S3 Bucket Logging
func (e *SyncEngine) s3BucketLoggingTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_loggings",
		Columns: []string{"arn", "account_id", "region", "bucket", "target_bucket", "target_prefix"},
		Fetch:   e.fetchS3BucketLogging,
	}
}

func (e *SyncEngine) fetchS3BucketLogging(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		logOut, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_loggings", bucketName, bucketRegion, "GetBucketLogging", err)
			continue
		}

		var targetBucket, targetPrefix string
		if logOut.LoggingEnabled != nil {
			targetBucket = aws.ToString(logOut.LoggingEnabled.TargetBucket)
			targetPrefix = aws.ToString(logOut.LoggingEnabled.TargetPrefix)
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/logging", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":        arn,
			"arn":           arn,
			"account_id":    accountID,
			"region":        bucketRegion,
			"bucket":        bucketName,
			"target_bucket": targetBucket,
			"target_prefix": targetPrefix,
		})
	}
	return rows, nil
}

// S3 Bucket Public Access Block
func (e *SyncEngine) s3BucketPublicAccessBlockTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_public_access_blocks",
		Columns: []string{"arn", "account_id", "region", "bucket", "block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"},
		Fetch:   e.fetchS3BucketPublicAccessBlock,
	}
}

func (e *SyncEngine) fetchS3BucketPublicAccessBlock(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		pabOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_public_access_blocks", bucketName, bucketRegion, "GetPublicAccessBlock", err, "NoSuchPublicAccessBlockConfiguration")
			// No public access block config - record as all false
			arn := fmt.Sprintf("arn:aws:s3:::%s/public-access-block", bucketName)
			rows = append(rows, map[string]interface{}{
				"_cq_id":                  arn,
				"arn":                     arn,
				"account_id":              accountID,
				"region":                  bucketRegion,
				"bucket":                  bucketName,
				"block_public_acls":       false,
				"ignore_public_acls":      false,
				"block_public_policy":     false,
				"restrict_public_buckets": false,
			})
			continue
		}

		cfg := pabOut.PublicAccessBlockConfiguration
		arn := fmt.Sprintf("arn:aws:s3:::%s/public-access-block", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":                  arn,
			"arn":                     arn,
			"account_id":              accountID,
			"region":                  bucketRegion,
			"bucket":                  bucketName,
			"block_public_acls":       aws.ToBool(cfg.BlockPublicAcls),
			"ignore_public_acls":      aws.ToBool(cfg.IgnorePublicAcls),
			"block_public_policy":     aws.ToBool(cfg.BlockPublicPolicy),
			"restrict_public_buckets": aws.ToBool(cfg.RestrictPublicBuckets),
		})
	}
	return rows, nil
}

// S3 Bucket Ownership Controls
func (e *SyncEngine) s3BucketOwnershipControlsTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_ownership_controls",
		Columns: []string{"arn", "account_id", "region", "bucket", "object_ownership", "rules"},
		Fetch:   e.fetchS3BucketOwnershipControls,
	}
}

func (e *SyncEngine) fetchS3BucketOwnershipControls(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		var rules interface{}
		objectOwnership := ""
		ownershipOut, err := client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
			Bucket: aws.String(bucketName),
		})
		e.warnS3BucketOperation("aws_s3_bucket_ownership_controls", bucketName, bucketRegion, "GetBucketOwnershipControls", err, "OwnershipControlsNotFoundError")
		if err == nil && ownershipOut.OwnershipControls != nil {
			rules = ownershipOut.OwnershipControls.Rules
			if len(ownershipOut.OwnershipControls.Rules) > 0 {
				objectOwnership = string(ownershipOut.OwnershipControls.Rules[0].ObjectOwnership)
			}
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/ownership-controls", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":           arn,
			"arn":              arn,
			"account_id":       accountID,
			"region":           bucketRegion,
			"bucket":           bucketName,
			"object_ownership": objectOwnership,
			"rules":            rules,
		})
	}

	return rows, nil
}

// S3 Bucket Policy Status
func (e *SyncEngine) s3BucketPolicyStatusTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_policy_statuses",
		Columns: []string{"arn", "account_id", "region", "bucket", "is_public"},
		Fetch:   e.fetchS3BucketPolicyStatuses,
	}
}

func (e *SyncEngine) fetchS3BucketPolicyStatuses(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		isPublic := false
		statusOut, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: aws.String(bucketName),
		})
		e.warnS3BucketOperation("aws_s3_bucket_policy_statuses", bucketName, bucketRegion, "GetBucketPolicyStatus", err, "NoSuchBucketPolicy")
		if err == nil && statusOut.PolicyStatus != nil {
			isPublic = aws.ToBool(statusOut.PolicyStatus.IsPublic)
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/policy-status", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":     arn,
			"arn":        arn,
			"account_id": accountID,
			"region":     bucketRegion,
			"bucket":     bucketName,
			"is_public":  isPublic,
		})
	}

	return rows, nil
}

// S3 Bucket Notifications
func (e *SyncEngine) s3BucketNotificationTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_notifications",
		Columns: []string{"arn", "account_id", "region", "bucket", "topic_configurations", "queue_configurations", "lambda_function_configurations", "event_bridge_configuration"},
		Fetch:   e.fetchS3BucketNotifications,
	}
}

func (e *SyncEngine) fetchS3BucketNotifications(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		conf, err := client.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_notifications", bucketName, bucketRegion, "GetBucketNotificationConfiguration", err)
			continue
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/notification", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":                         arn,
			"arn":                            arn,
			"account_id":                     accountID,
			"region":                         bucketRegion,
			"bucket":                         bucketName,
			"topic_configurations":           conf.TopicConfigurations,
			"queue_configurations":           conf.QueueConfigurations,
			"lambda_function_configurations": conf.LambdaFunctionConfigurations,
			"event_bridge_configuration":     conf.EventBridgeConfiguration,
		})
	}

	return rows, nil
}

// S3 Bucket Inventory Configurations
func (e *SyncEngine) s3BucketInventoryTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_inventory_configurations",
		Columns: []string{"arn", "account_id", "region", "bucket", "inventory_id", "is_enabled", "included_object_versions", "optional_fields", "destination", "schedule", "filter"},
		Fetch:   e.fetchS3BucketInventoryConfigurations,
	}
}

func (e *SyncEngine) fetchS3BucketInventoryConfigurations(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		var continuationToken *string
		for {
			out, err := client.ListBucketInventoryConfigurations(ctx, &s3.ListBucketInventoryConfigurationsInput{
				Bucket:            aws.String(bucketName),
				ContinuationToken: continuationToken,
			})
			if err != nil {
				e.warnS3BucketOperation("aws_s3_bucket_inventory_configurations", bucketName, bucketRegion, "ListBucketInventoryConfigurations", err)
				break
			}
			for _, cfg := range out.InventoryConfigurationList {
				inventoryID := aws.ToString(cfg.Id)
				arn := fmt.Sprintf("arn:aws:s3:::%s/inventory/%s", bucketName, inventoryID)
				rows = append(rows, map[string]interface{}{
					"_cq_id":                   arn,
					"arn":                      arn,
					"account_id":               accountID,
					"region":                   bucketRegion,
					"bucket":                   bucketName,
					"inventory_id":             inventoryID,
					"is_enabled":               cfg.IsEnabled,
					"included_object_versions": string(cfg.IncludedObjectVersions),
					"optional_fields":          cfg.OptionalFields,
					"destination":              cfg.Destination,
					"schedule":                 cfg.Schedule,
					"filter":                   cfg.Filter,
				})
			}

			if !aws.ToBool(out.IsTruncated) {
				break
			}
			continuationToken = out.NextContinuationToken
		}
	}

	return rows, nil
}

// S3 Bucket Object Lock Configuration
func (e *SyncEngine) s3BucketObjectLockTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_object_lock_configurations",
		Columns: []string{"arn", "account_id", "region", "bucket", "object_lock_enabled", "rule"},
		Fetch:   e.fetchS3BucketObjectLockConfigurations,
	}
}

func (e *SyncEngine) fetchS3BucketObjectLockConfigurations(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		lockOut, err := client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: aws.String(bucketName),
		})
		e.warnS3BucketOperation("aws_s3_bucket_object_lock_configurations", bucketName, bucketRegion, "GetObjectLockConfiguration", err, "ObjectLockConfigurationNotFoundError")
		if err != nil || lockOut.ObjectLockConfiguration == nil {
			continue
		}

		cfg := lockOut.ObjectLockConfiguration
		arn := fmt.Sprintf("arn:aws:s3:::%s/object-lock", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":              arn,
			"arn":                 arn,
			"account_id":          accountID,
			"region":              bucketRegion,
			"bucket":              bucketName,
			"object_lock_enabled": string(cfg.ObjectLockEnabled),
			"rule":                cfg.Rule,
		})
	}

	return rows, nil
}

// S3 Access Points
func (e *SyncEngine) s3AccessPointTable() TableSpec {
	return TableSpec{
		Name: "aws_s3_access_points",
		Columns: []string{
			"arn", "account_id", "region", "access_point_name", "access_point_arn", "bucket",
			"bucket_account_id", "network_origin", "vpc_id", "public_access_block_configuration",
			"creation_date", "alias",
		},
		Fetch: e.fetchS3AccessPoints,
	}
}

func (e *SyncEngine) fetchS3AccessPoints(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	if accountID == "" {
		return nil, nil
	}

	client := s3control.NewFromConfig(cfg, func(o *s3control.Options) {
		o.Region = region
	})

	paginator := s3control.NewListAccessPointsPaginator(client, &s3control.ListAccessPointsInput{
		AccountId: aws.String(accountID),
	})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, ap := range page.AccessPointList {
			name := aws.ToString(ap.Name)
			apArn := aws.ToString(ap.AccessPointArn)
			if apArn == "" {
				apArn = fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/%s", region, accountID, name)
			}
			networkOrigin := string(ap.NetworkOrigin)
			vpcID := ""
			if ap.VpcConfiguration != nil {
				vpcID = aws.ToString(ap.VpcConfiguration.VpcId)
			}

			var publicAccessBlock interface{}
			var creationDate interface{}
			detail, err := client.GetAccessPoint(ctx, &s3control.GetAccessPointInput{
				AccountId: aws.String(accountID),
				Name:      ap.Name,
			})
			if err == nil {
				if detail.PublicAccessBlockConfiguration != nil {
					publicAccessBlock = detail.PublicAccessBlockConfiguration
				}
				creationDate = detail.CreationDate
				if detail.VpcConfiguration != nil {
					vpcID = aws.ToString(detail.VpcConfiguration.VpcId)
				}
				if detail.NetworkOrigin != "" {
					networkOrigin = string(detail.NetworkOrigin)
				}
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                            apArn,
				"arn":                               apArn,
				"account_id":                        accountID,
				"region":                            region,
				"access_point_name":                 name,
				"access_point_arn":                  apArn,
				"bucket":                            aws.ToString(ap.Bucket),
				"bucket_account_id":                 aws.ToString(ap.BucketAccountId),
				"network_origin":                    networkOrigin,
				"vpc_id":                            vpcID,
				"public_access_block_configuration": publicAccessBlock,
				"creation_date":                     creationDate,
				"alias":                             aws.ToString(ap.Alias),
			})
		}
	}

	return rows, nil
}

// S3 Bucket Lifecycle
func (e *SyncEngine) s3BucketLifecycleTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_lifecycles",
		Columns: []string{"arn", "account_id", "region", "bucket", "rule_id", "status", "prefix", "expiration_days", "expiration_date", "noncurrent_version_expiration_days", "abort_incomplete_multipart_upload_days", "transitions"},
		Fetch:   e.fetchS3BucketLifecycle,
	}
}

func (e *SyncEngine) fetchS3BucketLifecycle(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		lcOut, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_lifecycles", bucketName, bucketRegion, "GetBucketLifecycleConfiguration", err, "NoSuchLifecycleConfiguration")
			continue // No lifecycle config
		}

		for _, rule := range lcOut.Rules {
			ruleID := aws.ToString(rule.ID)
			arn := fmt.Sprintf("arn:aws:s3:::%s/lifecycle/%s", bucketName, ruleID)

			var expDays, expDate interface{}
			if rule.Expiration != nil {
				if rule.Expiration.Days != nil {
					expDays = *rule.Expiration.Days
				}
				expDate = rule.Expiration.Date
			}

			var ncvExpDays interface{}
			if rule.NoncurrentVersionExpiration != nil && rule.NoncurrentVersionExpiration.NoncurrentDays != nil {
				ncvExpDays = *rule.NoncurrentVersionExpiration.NoncurrentDays
			}

			var abortDays interface{}
			if rule.AbortIncompleteMultipartUpload != nil && rule.AbortIncompleteMultipartUpload.DaysAfterInitiation != nil {
				abortDays = *rule.AbortIncompleteMultipartUpload.DaysAfterInitiation
			}

			var transitions []map[string]interface{}
			for _, t := range rule.Transitions {
				trans := map[string]interface{}{
					"storage_class": string(t.StorageClass),
				}
				if t.Days != nil {
					trans["days"] = *t.Days
				}
				if t.Date != nil {
					trans["date"] = t.Date
				}
				transitions = append(transitions, trans)
			}

			var prefix string
			if rule.Filter != nil {
				if rule.Filter.Prefix != nil {
					prefix = *rule.Filter.Prefix
				}
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                                 arn,
				"arn":                                    arn,
				"account_id":                             accountID,
				"region":                                 bucketRegion,
				"bucket":                                 bucketName,
				"rule_id":                                ruleID,
				"status":                                 string(rule.Status),
				"prefix":                                 prefix,
				"expiration_days":                        expDays,
				"expiration_date":                        expDate,
				"noncurrent_version_expiration_days":     ncvExpDays,
				"abort_incomplete_multipart_upload_days": abortDays,
				"transitions":                            transitions,
			})
		}
	}
	return rows, nil
}

// S3 Bucket Replication
func (e *SyncEngine) s3BucketReplicationTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_replications",
		Columns: []string{"arn", "account_id", "region", "bucket", "role", "rules"},
		Fetch:   e.fetchS3BucketReplication,
	}
}

func (e *SyncEngine) fetchS3BucketReplication(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		repOut, err := client.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_replications", bucketName, bucketRegion, "GetBucketReplication", err, "ReplicationConfigurationNotFoundError")
			continue // No replication config
		}

		if repOut.ReplicationConfiguration != nil {
			arn := fmt.Sprintf("arn:aws:s3:::%s/replication", bucketName)
			rows = append(rows, map[string]interface{}{
				"_cq_id":     arn,
				"arn":        arn,
				"account_id": accountID,
				"region":     bucketRegion,
				"bucket":     bucketName,
				"role":       aws.ToString(repOut.ReplicationConfiguration.Role),
				"rules":      repOut.ReplicationConfiguration.Rules,
			})
		}
	}
	return rows, nil
}

// S3 Bucket CORS Rules
func (e *SyncEngine) s3BucketCorsTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_cors_rules",
		Columns: []string{"arn", "account_id", "region", "bucket", "allowed_headers", "allowed_methods", "allowed_origins", "expose_headers", "max_age_seconds"},
		Fetch:   e.fetchS3BucketCors,
	}
}

// S3 Object Inventory
func (e *SyncEngine) s3ObjectTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_objects",
		Columns: []string{"arn", "account_id", "region", "bucket", "key", "etag", "size", "storage_class", "last_modified", "owner", "restore_status"},
		Fetch:   e.fetchS3Objects,
	}
}

func (e *SyncEngine) fetchS3Objects(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		pager := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
		})

		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, obj := range page.Contents {
				key := aws.ToString(obj.Key)
				arn := fmt.Sprintf("arn:aws:s3:::%s/%s", bucketName, key)
				row := map[string]interface{}{
					"_cq_id":        arn,
					"arn":           arn,
					"account_id":    accountID,
					"region":        bucketRegion,
					"bucket":        bucketName,
					"key":           key,
					"etag":          aws.ToString(obj.ETag),
					"size":          obj.Size,
					"storage_class": string(obj.StorageClass),
					"last_modified": obj.LastModified,
				}

				if obj.Owner != nil {
					row["owner"] = map[string]interface{}{
						"display_name": aws.ToString(obj.Owner.DisplayName),
						"id":           aws.ToString(obj.Owner.ID),
					}
				}

				if obj.RestoreStatus != nil {
					row["restore_status"] = map[string]interface{}{
						"is_restore_in_progress": aws.ToBool(obj.RestoreStatus.IsRestoreInProgress),
						"restore_expiry_date":    obj.RestoreStatus.RestoreExpiryDate,
					}
				}

				rows = append(rows, row)
			}
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchS3BucketCors(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		corsOut, err := client.GetBucketCors(ctx, &s3.GetBucketCorsInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_cors_rules", bucketName, bucketRegion, "GetBucketCors", err, "NoSuchCORSConfiguration")
			continue // No CORS config
		}

		for i, rule := range corsOut.CORSRules {
			arn := fmt.Sprintf("arn:aws:s3:::%s/cors/%d", bucketName, i)
			rows = append(rows, map[string]interface{}{
				"_cq_id":          arn,
				"arn":             arn,
				"account_id":      accountID,
				"region":          bucketRegion,
				"bucket":          bucketName,
				"allowed_headers": rule.AllowedHeaders,
				"allowed_methods": rule.AllowedMethods,
				"allowed_origins": rule.AllowedOrigins,
				"expose_headers":  rule.ExposeHeaders,
				"max_age_seconds": rule.MaxAgeSeconds,
			})
		}
	}
	return rows, nil
}

// S3 Bucket Website
func (e *SyncEngine) s3BucketWebsiteTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_bucket_websites",
		Columns: []string{"arn", "account_id", "region", "bucket", "index_document", "error_document", "redirect_all_requests_to"},
		Fetch:   e.fetchS3BucketWebsite,
	}
}

func (e *SyncEngine) fetchS3BucketWebsite(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := newS3BucketRegionalClient(cfg, region)
	accountID := e.getAccountIDFromConfig(ctx, cfg)
	buckets, err := e.s3BucketsInRegion(ctx, cfg, region)
	if err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	for _, bucket := range buckets {
		bucketName := bucket.Name
		bucketRegion := bucket.Region

		webOut, err := client.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			e.warnS3BucketOperation("aws_s3_bucket_websites", bucketName, bucketRegion, "GetBucketWebsite", err, "NoSuchWebsiteConfiguration")
			continue // No website config
		}

		var indexDoc, errorDoc string
		var redirectAll interface{}
		if webOut.IndexDocument != nil {
			indexDoc = aws.ToString(webOut.IndexDocument.Suffix)
		}
		if webOut.ErrorDocument != nil {
			errorDoc = aws.ToString(webOut.ErrorDocument.Key)
		}
		if webOut.RedirectAllRequestsTo != nil {
			redirectAll = map[string]string{
				"host_name": aws.ToString(webOut.RedirectAllRequestsTo.HostName),
				"protocol":  string(webOut.RedirectAllRequestsTo.Protocol),
			}
		}

		arn := fmt.Sprintf("arn:aws:s3:::%s/website", bucketName)
		rows = append(rows, map[string]interface{}{
			"_cq_id":                   arn,
			"arn":                      arn,
			"account_id":               accountID,
			"region":                   bucketRegion,
			"bucket":                   bucketName,
			"index_document":           indexDoc,
			"error_document":           errorDoc,
			"redirect_all_requests_to": redirectAll,
		})
	}
	return rows, nil
}

// Ensure types package is used (required for type assertions in fetch functions)
var _ types.BucketLocationConstraint
