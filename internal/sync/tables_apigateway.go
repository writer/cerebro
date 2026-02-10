package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func (e *SyncEngine) apiGatewayRestApiTable() TableSpec {
	return TableSpec{
		Name: "aws_apigateway_rest_apis",
		Columns: []string{
			"arn", "id", "name", "region", "account_id", "description",
			"created_date", "api_key_source", "endpoint_configuration",
			"minimum_compression_size", "policy", "tags", "version",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := apigateway.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("get rest apis: %w", err)
				}

				for _, api := range page.Items {
					apiID := ptrToStr(api.Id)
					arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiID)

					row := map[string]interface{}{
						"_cq_id":                   arn,
						"arn":                      arn,
						"id":                       apiID,
						"name":                     ptrToStr(api.Name),
						"region":                   region,
						"account_id":               e.accountID,
						"description":              ptrToStr(api.Description),
						"created_date":             api.CreatedDate,
						"api_key_source":           string(api.ApiKeySource),
						"endpoint_configuration":   api.EndpointConfiguration,
						"minimum_compression_size": api.MinimumCompressionSize,
						"policy":                   ptrToStr(api.Policy),
						"tags":                     api.Tags,
						"version":                  ptrToStr(api.Version),
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) apiGatewayMethodTable() TableSpec {
	return TableSpec{
		Name: "aws_apigateway_rest_api_methods",
		Columns: []string{
			"arn", "rest_api_id", "resource_id", "resource_path", "http_method",
			"authorization_type", "api_key_required", "authorizer_id",
			"request_parameters", "request_models", "operation_name",
			"region", "account_id",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := apigateway.NewFromConfig(cfg)
			var results []map[string]interface{}

			apiPager := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})
			for apiPager.HasMorePages() {
				apiPage, err := apiPager.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("get rest apis: %w", err)
				}

				for _, api := range apiPage.Items {
					apiID := ptrToStr(api.Id)
					resPager := apigateway.NewGetResourcesPaginator(client, &apigateway.GetResourcesInput{
						RestApiId: api.Id,
						Embed:     []string{"methods"},
					})

					for resPager.HasMorePages() {
						resPage, err := resPager.NextPage(ctx)
						if err != nil {
							return nil, fmt.Errorf("get resources for api %s: %w", apiID, err)
						}

						for _, resource := range resPage.Items {
							if len(resource.ResourceMethods) == 0 {
								continue
							}

							resourceID := ptrToStr(resource.Id)
							resourcePath := ptrToStr(resource.Path)
							for method, methodInfo := range resource.ResourceMethods {
								methodName := strings.ToUpper(method)
								arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/resources/%s/methods/%s", region, apiID, resourceID, methodName)

								row := map[string]interface{}{
									"_cq_id":             arn,
									"arn":                arn,
									"rest_api_id":        apiID,
									"resource_id":        resourceID,
									"resource_path":      resourcePath,
									"http_method":        methodName,
									"authorization_type": aws.ToString(methodInfo.AuthorizationType),
									"api_key_required":   aws.ToBool(methodInfo.ApiKeyRequired),
									"authorizer_id":      aws.ToString(methodInfo.AuthorizerId),
									"request_parameters": methodInfo.RequestParameters,
									"request_models":     methodInfo.RequestModels,
									"operation_name":     aws.ToString(methodInfo.OperationName),
									"region":             region,
									"account_id":         e.accountID,
								}

								results = append(results, row)
							}
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) apiGatewayStageTable() TableSpec {
	return TableSpec{
		Name: "aws_apigateway_stages",
		Columns: []string{
			"arn", "rest_api_id", "stage_name", "region", "account_id",
			"deployment_id", "description", "cache_cluster_enabled",
			"cache_cluster_size", "cache_cluster_status", "method_settings",
			"variables", "access_log_settings", "tracing_enabled",
			"web_acl_arn", "created_date", "last_updated_date", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := apigateway.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all REST APIs first
			apiPager := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

			for apiPager.HasMorePages() {
				apiPage, err := apiPager.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, api := range apiPage.Items {
					apiID := ptrToStr(api.Id)

					// Get stages for this API
					stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{
						RestApiId: api.Id,
					})
					if err != nil {
						continue
					}

					for _, stage := range stages.Item {
						stageName := ptrToStr(stage.StageName)
						arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", region, apiID, stageName)

						row := map[string]interface{}{
							"_cq_id":                arn,
							"arn":                   arn,
							"rest_api_id":           apiID,
							"stage_name":            stageName,
							"region":                region,
							"account_id":            e.accountID,
							"deployment_id":         ptrToStr(stage.DeploymentId),
							"description":           ptrToStr(stage.Description),
							"cache_cluster_enabled": stage.CacheClusterEnabled,
							"cache_cluster_size":    string(stage.CacheClusterSize),
							"cache_cluster_status":  string(stage.CacheClusterStatus),
							"method_settings":       stage.MethodSettings,
							"variables":             stage.Variables,
							"access_log_settings":   stage.AccessLogSettings,
							"tracing_enabled":       stage.TracingEnabled,
							"web_acl_arn":           ptrToStr(stage.WebAclArn),
							"created_date":          stage.CreatedDate,
							"last_updated_date":     stage.LastUpdatedDate,
							"tags":                  stage.Tags,
						}

						results = append(results, row)
					}
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) apiGatewayV2ApiTable() TableSpec {
	return TableSpec{
		Name: "aws_apigatewayv2_apis",
		Columns: []string{
			"arn", "api_id", "name", "region", "account_id", "description",
			"api_endpoint", "protocol_type", "route_selection_expression",
			"api_key_selection_expression", "cors_configuration",
			"disable_execute_api_endpoint", "created_date", "tags", "version",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := apigatewayv2.NewFromConfig(cfg)
			var results []map[string]interface{}
			var nextToken *string

			for {
				page, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, fmt.Errorf("get apis v2: %w", err)
				}

				for _, api := range page.Items {
					apiID := ptrToStr(api.ApiId)
					arn := fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", region, apiID)

					row := map[string]interface{}{
						"_cq_id":                       arn,
						"arn":                          arn,
						"api_id":                       apiID,
						"name":                         ptrToStr(api.Name),
						"region":                       region,
						"account_id":                   e.accountID,
						"description":                  ptrToStr(api.Description),
						"api_endpoint":                 ptrToStr(api.ApiEndpoint),
						"protocol_type":                string(api.ProtocolType),
						"route_selection_expression":   ptrToStr(api.RouteSelectionExpression),
						"api_key_selection_expression": ptrToStr(api.ApiKeySelectionExpression),
						"cors_configuration":           api.CorsConfiguration,
						"disable_execute_api_endpoint": api.DisableExecuteApiEndpoint,
						"created_date":                 api.CreatedDate,
						"tags":                         api.Tags,
						"version":                      ptrToStr(api.Version),
					}

					results = append(results, row)
				}

				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) apiGatewayV2StageTable() TableSpec {
	return TableSpec{
		Name: "aws_apigatewayv2_stages",
		Columns: []string{
			"arn", "api_id", "stage_name", "region", "account_id",
			"deployment_id", "description", "auto_deploy",
			"default_route_settings", "route_settings", "stage_variables",
			"access_log_settings", "created_date", "last_updated_date", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := apigatewayv2.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all APIs first
			var apiNextToken *string
			for {
				apiPage, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{
					NextToken: apiNextToken,
				})
				if err != nil {
					break
				}

				for _, api := range apiPage.Items {
					apiID := ptrToStr(api.ApiId)

					// Get stages for this API
					var stageNextToken *string
					for {
						stagePage, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{
							ApiId:     api.ApiId,
							NextToken: stageNextToken,
						})
						if err != nil {
							break
						}

						for _, stage := range stagePage.Items {
							stageName := ptrToStr(stage.StageName)
							arn := fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s/stages/%s", region, apiID, stageName)

							row := map[string]interface{}{
								"_cq_id":                 arn,
								"arn":                    arn,
								"api_id":                 apiID,
								"stage_name":             stageName,
								"region":                 region,
								"account_id":             e.accountID,
								"deployment_id":          ptrToStr(stage.DeploymentId),
								"description":            ptrToStr(stage.Description),
								"auto_deploy":            stage.AutoDeploy,
								"default_route_settings": stage.DefaultRouteSettings,
								"route_settings":         stage.RouteSettings,
								"stage_variables":        stage.StageVariables,
								"access_log_settings":    stage.AccessLogSettings,
								"created_date":           stage.CreatedDate,
								"last_updated_date":      stage.LastUpdatedDate,
								"tags":                   stage.Tags,
							}

							results = append(results, row)
						}

						if stagePage.NextToken == nil {
							break
						}
						stageNextToken = stagePage.NextToken
					}
				}

				if apiPage.NextToken == nil {
					break
				}
				apiNextToken = apiPage.NextToken
			}

			return results, nil
		},
	}
}
