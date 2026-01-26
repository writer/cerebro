package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (e *SyncEngine) s3BucketTable() TableSpec {
	return TableSpec{
		Name:    "aws_s3_buckets",
		Columns: []string{"name", "arn", "creation_date", "region", "account_id", "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets", "versioning_status", "versioning_mfa_delete", "logging_target_bucket", "logging_target_prefix", "encryption", "tags"},
		Fetch:   e.fetchS3Buckets,
	}
}

func (e *SyncEngine) fetchS3Buckets(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	// S3 ListBuckets is global, only sync from us-east-1
	if region != "us-east-1" {
		return nil, nil
	}

	client := s3.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	listOut, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(listOut.Buckets))
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
			bucketRegion := string(loc.LocationConstraint)
			if bucketRegion == "" {
				bucketRegion = "us-east-1"
			}
			row["region"] = bucketRegion
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
	return rows, nil
}
