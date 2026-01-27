package sync

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
)

// Resource Groups Tagging API Resources table
func (e *SyncEngine) resourceGroupTaggingResourceTable() TableSpec {
	return TableSpec{
		Name: "aws_resourcegroupstagging_resources",
		Columns: []string{
			"_cq_hash", "arn", "account_id", "region", "service",
			"resource_type", "resource_id", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := resourcegroupstaggingapi.NewFromConfig(cfg, func(o *resourcegroupstaggingapi.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(client, &resourcegroupstaggingapi.GetResourcesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, mapping := range page.ResourceTagMappingList {
					arn := aws.ToString(mapping.ResourceARN)
					if arn == "" {
						continue
					}

					service, resourceType, resourceID := parseTaggedResourceArn(arn)
					tags := map[string]string{}
					for _, tag := range mapping.Tags {
						if tag.Key != nil && tag.Value != nil {
							tags[*tag.Key] = *tag.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"_cq_id":        arn,
						"arn":           arn,
						"account_id":    accountID,
						"region":        region,
						"service":       service,
						"resource_type": resourceType,
						"resource_id":   resourceID,
						"tags":          string(tagsJSON),
					}
					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func parseTaggedResourceArn(arn string) (service, resourceType, resourceID string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", "", ""
	}

	service = parts[2]
	resource := parts[5]
	if resource == "" {
		return service, "", ""
	}

	if idx := strings.IndexAny(resource, "/:"); idx >= 0 {
		resourceType = resource[:idx]
		resourceID = resource[idx+1:]
		return service, resourceType, resourceID
	}

	return service, resource, resource
}
