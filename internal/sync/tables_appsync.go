package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
)

func (e *SyncEngine) appsyncGraphQLApiTable() TableSpec {
	return TableSpec{
		Name: "aws_appsync_graphql_apis",
		Columns: []string{
			"arn", "api_id", "name", "region", "account_id",
			"authentication_type", "additional_authentication_providers",
			"log_config", "user_pool_config", "open_id_connect_config",
			"lambda_authorizer_config", "xray_enabled", "waf_web_acl_arn",
			"api_type", "merged_api_execution_role_arn", "visibility",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := appsync.NewFromConfig(cfg)
			var results []map[string]interface{}
			var nextToken *string

			for {
				listOut, err := client.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, fmt.Errorf("list graphql apis: %w", err)
				}

				for _, api := range listOut.GraphqlApis {
					arn := ptrToStr(api.Arn)
					apiID := ptrToStr(api.ApiId)

					row := map[string]interface{}{
						"_cq_id":                              arn,
						"arn":                                 arn,
						"api_id":                              apiID,
						"name":                                ptrToStr(api.Name),
						"region":                              region,
						"account_id":                          e.accountID,
						"authentication_type":                 string(api.AuthenticationType),
						"additional_authentication_providers": api.AdditionalAuthenticationProviders,
						"log_config":                          api.LogConfig,
						"user_pool_config":                    api.UserPoolConfig,
						"open_id_connect_config":              api.OpenIDConnectConfig,
						"lambda_authorizer_config":            api.LambdaAuthorizerConfig,
						"xray_enabled":                        api.XrayEnabled,
						"waf_web_acl_arn":                     ptrToStr(api.WafWebAclArn),
						"api_type":                            string(api.ApiType),
						"merged_api_execution_role_arn":       ptrToStr(api.MergedApiExecutionRoleArn),
						"visibility":                          string(api.Visibility),
					}

					results = append(results, row)
				}

				if listOut.NextToken == nil {
					break
				}
				nextToken = listOut.NextToken
			}

			return results, nil
		},
	}
}
