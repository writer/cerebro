package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
)

func (e *SyncEngine) ecrRepositoryTable() TableSpec {
	return TableSpec{
		Name: "aws_ecr_repositories",
		Columns: []string{
			"arn", "repository_name", "registry_id", "region", "account_id",
			"repository_uri", "created_at", "image_tag_mutability",
			"image_scanning_configuration", "encryption_configuration",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ecr.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe repositories: %w", err)
				}

				for _, repo := range page.Repositories {
					arn := ptrToStr(repo.RepositoryArn)

					var scanOnPush bool
					if repo.ImageScanningConfiguration != nil {
						scanOnPush = repo.ImageScanningConfiguration.ScanOnPush
					}

					row := map[string]interface{}{
						"_cq_id":                       arn,
						"arn":                          arn,
						"repository_name":              ptrToStr(repo.RepositoryName),
						"registry_id":                  ptrToStr(repo.RegistryId),
						"region":                       region,
						"account_id":                   e.accountID,
						"repository_uri":               ptrToStr(repo.RepositoryUri),
						"created_at":                   repo.CreatedAt,
						"image_tag_mutability":         string(repo.ImageTagMutability),
						"image_scanning_configuration": map[string]interface{}{"scan_on_push": scanOnPush},
						"encryption_configuration":     repo.EncryptionConfiguration,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ecrImageTable() TableSpec {
	return TableSpec{
		Name: "aws_ecr_images",
		Columns: []string{
			"arn", "repository_name", "registry_id", "region", "account_id",
			"image_digest", "image_tags", "image_pushed_at", "image_size_in_bytes",
			"image_scan_status", "image_scan_findings_summary",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ecr.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all repositories first
			repoPager := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})

			for repoPager.HasMorePages() {
				repoPage, err := repoPager.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, repo := range repoPage.Repositories {
					// List images in this repository
					imgPager := ecr.NewDescribeImagesPaginator(client, &ecr.DescribeImagesInput{
						RepositoryName: repo.RepositoryName,
					})

					for imgPager.HasMorePages() {
						imgPage, err := imgPager.NextPage(ctx)
						if err != nil {
							continue
						}

						for _, img := range imgPage.ImageDetails {
							arn := fmt.Sprintf("%s/image/%s", ptrToStr(repo.RepositoryArn), ptrToStr(img.ImageDigest))

							var scanStatus, scanSummary interface{}
							if img.ImageScanStatus != nil {
								scanStatus = map[string]interface{}{
									"status":      string(img.ImageScanStatus.Status),
									"description": ptrToStr(img.ImageScanStatus.Description),
								}
							}
							if img.ImageScanFindingsSummary != nil {
								scanSummary = img.ImageScanFindingsSummary
							}

							row := map[string]interface{}{
								"_cq_id":                      arn,
								"arn":                         arn,
								"repository_name":             ptrToStr(repo.RepositoryName),
								"registry_id":                 ptrToStr(img.RegistryId),
								"region":                      region,
								"account_id":                  e.accountID,
								"image_digest":                ptrToStr(img.ImageDigest),
								"image_tags":                  img.ImageTags,
								"image_pushed_at":             img.ImagePushedAt,
								"image_size_in_bytes":         img.ImageSizeInBytes,
								"image_scan_status":           scanStatus,
								"image_scan_findings_summary": scanSummary,
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ecrPublicRepositoryTable() TableSpec {
	return TableSpec{
		Name: "aws_ecr_public_repositories",
		Columns: []string{
			"arn", "repository_name", "registry_id", "region", "account_id",
			"repository_uri", "created_at",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			// ECR Public is only available in us-east-1
			if region != "us-east-1" {
				return nil, nil
			}

			client := ecrpublic.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ecrpublic.NewDescribeRepositoriesPaginator(client, &ecrpublic.DescribeRepositoriesInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					// ECR Public might not be enabled
					return results, nil
				}

				for _, repo := range page.Repositories {
					arn := ptrToStr(repo.RepositoryArn)

					row := map[string]interface{}{
						"_cq_id":          arn,
						"arn":             arn,
						"repository_name": ptrToStr(repo.RepositoryName),
						"registry_id":     ptrToStr(repo.RegistryId),
						"region":          region,
						"account_id":      e.accountID,
						"repository_uri":  ptrToStr(repo.RepositoryUri),
						"created_at":      repo.CreatedAt,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ecrLifecyclePolicyTable() TableSpec {
	return TableSpec{
		Name: "aws_ecr_lifecycle_policies",
		Columns: []string{
			"arn", "repository_name", "registry_id", "region", "account_id",
			"lifecycle_policy_text", "last_evaluated_at",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ecr.NewFromConfig(cfg)
			var results []map[string]interface{}

			repoPager := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})

			for repoPager.HasMorePages() {
				repoPage, err := repoPager.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, repo := range repoPage.Repositories {
					policy, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
						RepositoryName: repo.RepositoryName,
					})
					if err != nil {
						continue // Repository might not have a lifecycle policy
					}

					arn := fmt.Sprintf("%s/lifecycle-policy", ptrToStr(repo.RepositoryArn))

					row := map[string]interface{}{
						"_cq_id":                arn,
						"arn":                   arn,
						"repository_name":       ptrToStr(policy.RepositoryName),
						"registry_id":           ptrToStr(policy.RegistryId),
						"region":                region,
						"account_id":            e.accountID,
						"lifecycle_policy_text": ptrToStr(policy.LifecyclePolicyText),
						"last_evaluated_at":     policy.LastEvaluatedAt,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}
