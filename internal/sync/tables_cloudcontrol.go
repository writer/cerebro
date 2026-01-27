package sync

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformation_types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func (e *SyncEngine) cloudcontrolResourceTypeTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudcontrol_resource_types",
		Columns: []string{
			"_cq_hash", "type_name", "account_id", "region",
			"description", "schema", "provisioning_type", "visibility",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			cfnClient := cloudformation.NewFromConfig(cfg, func(o *cloudformation.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			typeSummaries, err := listCloudFormationResourceTypes(ctx, cfnClient)
			if err != nil {
				return nil, err
			}

			for _, summary := range typeSummaries {
				typeName := aws.ToString(summary.TypeName)
				if typeName == "" {
					continue
				}

				description := aws.ToString(summary.Description)
				schemaValue := interface{}(nil)
				provisioningType := ""
				visibility := ""

				detail, err := cfnClient.DescribeType(ctx, &cloudformation.DescribeTypeInput{
					Type:     cloudformation_types.RegistryTypeResource,
					TypeName: summary.TypeName,
				})
				if err == nil && detail != nil {
					if detail.Description != nil {
						description = aws.ToString(detail.Description)
					}
					schemaValue = parseCloudControlJSON(aws.ToString(detail.Schema))
					provisioningType = string(detail.ProvisioningType)
					visibility = string(detail.Visibility)
				}

				row := map[string]interface{}{
					"_cq_id":            fmt.Sprintf("%s:%s", region, typeName),
					"type_name":         typeName,
					"account_id":        accountID,
					"region":            region,
					"description":       description,
					"schema":            schemaValue,
					"provisioning_type": provisioningType,
					"visibility":        visibility,
				}
				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) cloudcontrolResourceTable() TableSpec {
	return TableSpec{
		Name: "aws_cloudcontrol_resources",
		Columns: []string{
			"_cq_hash", "type_name", "identifier", "properties", "account_id", "region",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cloudcontrol.NewFromConfig(cfg, func(o *cloudcontrol.Options) {
				o.Region = region
			})
			cfnClient := cloudformation.NewFromConfig(cfg, func(o *cloudformation.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			typeSummaries, err := listCloudFormationResourceTypes(ctx, cfnClient)
			if err != nil {
				return nil, err
			}

			for _, summary := range typeSummaries {
				typeName := aws.ToString(summary.TypeName)
				if typeName == "" {
					continue
				}

				resourcePaginator := cloudcontrol.NewListResourcesPaginator(client, &cloudcontrol.ListResourcesInput{
					TypeName: aws.String(typeName),
				})
				for resourcePaginator.HasMorePages() {
					resourcePage, err := resourcePaginator.NextPage(ctx)
					if err != nil {
						e.logger.Debug("cloudcontrol list resources failed", "type", typeName, "error", err)
						break
					}

					for _, resource := range resourcePage.ResourceDescriptions {
						identifier := aws.ToString(resource.Identifier)
						if identifier == "" {
							continue
						}

						propertiesValue := parseCloudControlJSON(aws.ToString(resource.Properties))
						row := map[string]interface{}{
							"_cq_id":     fmt.Sprintf("%s:%s:%s", region, typeName, identifier),
							"type_name":  typeName,
							"identifier": identifier,
							"properties": propertiesValue,
							"account_id": accountID,
							"region":     region,
						}
						results = append(results, row)
					}
				}
			}

			return results, nil
		},
	}
}

func listCloudFormationResourceTypes(ctx context.Context, client *cloudformation.Client) ([]cloudformation_types.TypeSummary, error) {
	filters := &cloudformation_types.TypeFilters{Category: cloudformation_types.CategoryAwsTypes}
	paginator := cloudformation.NewListTypesPaginator(client, &cloudformation.ListTypesInput{
		Type:       cloudformation_types.RegistryTypeResource,
		Visibility: cloudformation_types.VisibilityPublic,
		Filters:    filters,
	})

	var results []cloudformation_types.TypeSummary
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		results = append(results, page.TypeSummaries...)
	}

	return results, nil
}

func parseCloudControlJSON(raw string) interface{} {
	if raw == "" {
		return nil
	}

	var value interface{}
	if err := json.Unmarshal([]byte(raw), &value); err == nil {
		return value
	}

	return raw
}
