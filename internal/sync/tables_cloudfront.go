package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func (e *SyncEngine) cloudfrontDistributionTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudfront_distributions",
		Columns: []string{
			"arn", "id", "domain_name", "region", "account_id",
			"status", "enabled", "aliases", "origins", "default_cache_behavior",
			"cache_behaviors", "custom_error_responses", "comment",
			"price_class", "viewer_certificate", "restrictions",
			"web_acl_id", "http_version", "is_ipv6_enabled", "last_modified_time",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			// CloudFront is a global service, only sync from us-east-1
			if region != "us-east-1" {
				return nil, nil
			}

			client := cloudfront.NewFromConfig(cfg)
			var results []map[string]interface{}
			var marker *string

			for {
				listOut, err := client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{
					Marker: marker,
				})
				if err != nil {
					return nil, fmt.Errorf("list distributions: %w", err)
				}

				if listOut.DistributionList == nil {
					break
				}

				for _, dist := range listOut.DistributionList.Items {
					id := ptrToStr(dist.Id)
					arn := ptrToStr(dist.ARN)

					row := map[string]interface{}{
						"_cq_id":                 arn,
						"arn":                    arn,
						"id":                     id,
						"domain_name":            ptrToStr(dist.DomainName),
						"region":                 "global",
						"account_id":             e.accountID,
						"status":                 ptrToStr(dist.Status),
						"enabled":                dist.Enabled,
						"aliases":                dist.Aliases,
						"origins":                dist.Origins,
						"default_cache_behavior": dist.DefaultCacheBehavior,
						"cache_behaviors":        dist.CacheBehaviors,
						"custom_error_responses": dist.CustomErrorResponses,
						"comment":                ptrToStr(dist.Comment),
						"price_class":            string(dist.PriceClass),
						"viewer_certificate":     dist.ViewerCertificate,
						"restrictions":           dist.Restrictions,
						"web_acl_id":             ptrToStr(dist.WebACLId),
						"http_version":           string(dist.HttpVersion),
						"is_ipv6_enabled":        dist.IsIPV6Enabled,
						"last_modified_time":     dist.LastModifiedTime,
					}

					results = append(results, row)
				}

				if listOut.DistributionList.NextMarker == nil || !aws.ToBool(listOut.DistributionList.IsTruncated) {
					break
				}
				marker = listOut.DistributionList.NextMarker
			}

			return results, nil
		},
	}
}
