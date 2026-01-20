package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func (s *AWSSyncer) syncS3Buckets(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := s3.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_s3_buckets", []string{
		"name", "arn", "creation_date", "region", "account_id",
		"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets",
		"versioning_status", "versioning_mfa_delete",
		"logging_target_bucket", "logging_target_prefix",
		"encryption", "tags",
	}); err != nil {
		return nil, err
	}

	listOut, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var rows []map[string]interface{}
	for _, bucket := range listOut.Buckets {
		name := aws.ToString(bucket.Name)
		arn := fmt.Sprintf("arn:aws:s3:::%s", name)

		row := map[string]interface{}{
			"_cq_id":        arn,
			"name":          name,
			"arn":           arn,
			"account_id":    accountID,
			"creation_date": bucket.CreationDate,
		}

		// Get bucket location
		if loc, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &name}); err == nil {
			region := string(loc.LocationConstraint)
			if region == "" {
				region = "us-east-1"
			}
			row["region"] = region
		}

		// Get public access block
		if pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name}); err == nil && pab.PublicAccessBlockConfiguration != nil {
			row["block_public_acls"] = aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicAcls)
			row["block_public_policy"] = aws.ToBool(pab.PublicAccessBlockConfiguration.BlockPublicPolicy)
			row["ignore_public_acls"] = aws.ToBool(pab.PublicAccessBlockConfiguration.IgnorePublicAcls)
			row["restrict_public_buckets"] = aws.ToBool(pab.PublicAccessBlockConfiguration.RestrictPublicBuckets)
		} else {
			row["block_public_acls"] = false
			row["block_public_policy"] = false
			row["ignore_public_acls"] = false
			row["restrict_public_buckets"] = false
		}

		// Get versioning
		if vers, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name}); err == nil {
			row["versioning_status"] = string(vers.Status)
			row["versioning_mfa_delete"] = string(vers.MFADelete)
		}

		// Get logging
		if log, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &name}); err == nil && log.LoggingEnabled != nil {
			row["logging_target_bucket"] = aws.ToString(log.LoggingEnabled.TargetBucket)
			row["logging_target_prefix"] = aws.ToString(log.LoggingEnabled.TargetPrefix)
		}

		rows = append(rows, row)
	}

	changes, err := s.upsertRows(ctx, "aws_s3_buckets", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_s3_buckets", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncECRRepositories(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := ecr.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_ecr_repositories", []string{
		"arn", "account_id", "region", "repository_name", "name", "registry_id", "repository_uri",
		"image_tag_mutability", "image_scanning_configuration", "encryption_configuration",
		"created_at",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			rows = append(rows, map[string]interface{}{
				"_cq_id":                       aws.ToString(repo.RepositoryArn),
				"arn":                          aws.ToString(repo.RepositoryArn),
				"account_id":                   accountID,
				"region":                       s.region,
				"repository_name":              aws.ToString(repo.RepositoryName),
				"name":                         aws.ToString(repo.RepositoryName),
				"registry_id":                  aws.ToString(repo.RegistryId),
				"repository_uri":               aws.ToString(repo.RepositoryUri),
				"image_tag_mutability":         string(repo.ImageTagMutability),
				"image_scanning_configuration": repo.ImageScanningConfiguration,
				"encryption_configuration":     repo.EncryptionConfiguration,
				"created_at":                   repo.CreatedAt,
			})
		}
	}

	changes, err := s.upsertRows(ctx, "aws_ecr_repositories", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_ecr_repositories", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncKMSKeys(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := kms.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_kms_keys", []string{
		"arn", "account_id", "region", "key_id", "description", "key_state", "key_usage",
		"creation_date", "enabled", "key_manager", "origin",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}

		for _, key := range page.Keys {
			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil {
				continue
			}

			km := descOut.KeyMetadata
			rows = append(rows, map[string]interface{}{
				"_cq_id":        aws.ToString(km.Arn),
				"arn":           aws.ToString(km.Arn),
				"account_id":    accountID,
				"region":        s.region,
				"key_id":        aws.ToString(km.KeyId),
				"description":   aws.ToString(km.Description),
				"key_state":     string(km.KeyState),
				"key_usage":     string(km.KeyUsage),
				"creation_date": km.CreationDate,
				"enabled":       km.Enabled,
				"key_manager":   string(km.KeyManager),
				"origin":        string(km.Origin),
			})
		}
	}

	changes, err := s.upsertRows(ctx, "aws_kms_keys", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_kms_keys", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncSecretsManagerSecrets(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := secretsmanager.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_secretsmanager_secrets", []string{
		"arn", "account_id", "region", "name", "description", "kms_key_id", "rotation_enabled",
		"rotation_lambda_arn", "last_changed_date", "last_accessed_date",
		"deleted_date", "tags",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}

		for _, secret := range page.SecretList {
			rows = append(rows, map[string]interface{}{
				"_cq_id":              aws.ToString(secret.ARN),
				"arn":                 aws.ToString(secret.ARN),
				"account_id":          accountID,
				"region":              s.region,
				"name":                aws.ToString(secret.Name),
				"description":         aws.ToString(secret.Description),
				"kms_key_id":          aws.ToString(secret.KmsKeyId),
				"rotation_enabled":    aws.ToBool(secret.RotationEnabled),
				"rotation_lambda_arn": aws.ToString(secret.RotationLambdaARN),
				"last_changed_date":   secret.LastChangedDate,
				"last_accessed_date":  secret.LastAccessedDate,
				"deleted_date":        secret.DeletedDate,
				"tags":                secret.Tags,
			})
		}
	}

	changes, err := s.upsertRows(ctx, "aws_secretsmanager_secrets", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_secretsmanager_secrets", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}
