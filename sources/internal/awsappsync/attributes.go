package awsappsync

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
)

// EventData builds the JSON payload, attribute map, and event ID for an AppSync GraphQL API record.
func EventData(settings Settings, record GraphQLAPI) ([]byte, map[string]string, string, error) {
	api := record.GraphqlApi
	arn := awssdk.ToString(api.Arn)
	apiID := awssdk.ToString(api.ApiId)
	name := firstNonEmpty(awssdk.ToString(api.Name), resourceName(arn), apiID)
	tags := firstTags(record.Tags, api.Tags)
	attributes := commonCloudAssetAttributes(settings, firstNonEmpty(arn, apiID, name), name, tags)
	putAttributes(attributes, map[string]string{
		"arn":                             arn,
		"api_arn":                         arn,
		"api_id":                          apiID,
		"api_name":                        name,
		"api_type":                        string(api.ApiType),
		"authentication_type":             string(api.AuthenticationType),
		"additional_authentication_types": strings.Join(additionalAuthTypes(api), ","),
		"authorization_modes":             strings.Join(authorizationModes(api), ","),
		"visibility":                      string(api.Visibility),
		"introspection_config":            string(api.IntrospectionConfig),
		"waf_web_acl_arn":                 awssdk.ToString(api.WafWebAclArn),
		"waf_enabled":                     boolString(awssdk.ToString(api.WafWebAclArn) != ""),
		"xray_enabled":                    boolString(api.XrayEnabled),
		"graphql_url":                     endpoint(api, "GRAPHQL"),
		"realtime_url":                    endpoint(api, "REALTIME"),
		"api_owner":                       awssdk.ToString(api.Owner),
		"api_owner_contact":               awssdk.ToString(api.OwnerContact),
		"data_source_count":               strconv.Itoa(len(record.DataSources)),
		"data_source_names":               strings.Join(dataSourceNames(record.DataSources), ","),
		"data_source_role_arns":           strings.Join(dataSourceRoleARNs(record.DataSources), ","),
		"data_source_types":               strings.Join(dataSourceTypes(record.DataSources), ","),
		"resolver_count":                  strconv.Itoa(len(record.Resolvers)),
		"resolver_data_source_names":      strings.Join(resolverDataSourceNames(record.Resolvers), ","),
		"resolver_fields":                 strings.Join(resolverFields(record.Resolvers), ","),
		"resolver_kinds":                  strings.Join(resolverKinds(record.Resolvers), ","),
		"type_count":                      strconv.Itoa(len(record.Types)),
		"type_names":                      strings.Join(typeNames(record.Types), ","),
	})
	if api.LogConfig != nil {
		attributes["field_log_level"] = string(api.LogConfig.FieldLogLevel)
		attributes["logging_enabled"] = boolString(api.LogConfig.FieldLogLevel != "" && api.LogConfig.FieldLogLevel != appsynctypes.FieldLogLevelNone)
		attributes["exclude_verbose_content"] = boolString(api.LogConfig.ExcludeVerboseContent)
		attributes["cloudwatch_logs_role_arn"] = awssdk.ToString(api.LogConfig.CloudWatchLogsRoleArn)
	} else {
		attributes["logging_enabled"] = "false"
	}
	if api.UserPoolConfig != nil {
		attributes["user_pool_id"] = awssdk.ToString(api.UserPoolConfig.UserPoolId)
		attributes["user_pool_region"] = awssdk.ToString(api.UserPoolConfig.AwsRegion)
		attributes["user_pool_default_action"] = string(api.UserPoolConfig.DefaultAction)
	} else if config := additionalUserPoolConfig(api); config != nil {
		attributes["user_pool_id"] = awssdk.ToString(config.UserPoolId)
		attributes["user_pool_region"] = awssdk.ToString(config.AwsRegion)
	}
	if config := openIDConnectConfig(api); config != nil {
		attributes["openid_connect_issuer"] = awssdk.ToString(config.Issuer)
	}
	if config := lambdaAuthorizerConfig(api); config != nil {
		attributes["lambda_authorizer_uri"] = awssdk.ToString(config.AuthorizerUri)
		if config.AuthorizerResultTtlInSeconds != 0 {
			attributes["lambda_authorizer_ttl_seconds"] = strconv.FormatInt(int64(config.AuthorizerResultTtlInSeconds), 10)
		}
	}
	if api.QueryDepthLimit != 0 {
		attributes["query_depth_limit"] = strconv.FormatInt(int64(api.QueryDepthLimit), 10)
	}
	if api.ResolverCountLimit != 0 {
		attributes["resolver_count_limit"] = strconv.FormatInt(int64(api.ResolverCountLimit), 10)
	}
	payload, err := json.Marshal(appSyncPayload(settings, record))
	return payload, attributes, "aws-appsync-graphql-api-" + firstNonEmpty(arn, apiID, name), err
}

func appSyncPayload(settings Settings, record GraphQLAPI) map[string]any {
	return map[string]any{
		"account_id":   settings.AccountID,
		"region":       settings.Region,
		"api":          record.GraphqlApi,
		"data_sources": record.DataSources,
		"types":        record.Types,
		"resolvers":    sanitizedResolvers(record.Resolvers),
		"tags":         firstTags(record.Tags, record.GraphqlApi.Tags),
	}
}

type sanitizedResolver struct {
	CachingConfig  *appsynctypes.CachingConfig             `json:"caching_config,omitempty"`
	DataSourceName *string                                 `json:"data_source_name,omitempty"`
	FieldName      *string                                 `json:"field_name,omitempty"`
	Kind           appsynctypes.ResolverKind               `json:"kind,omitempty"`
	MaxBatchSize   int32                                   `json:"max_batch_size,omitempty"`
	MetricsConfig  appsynctypes.ResolverLevelMetricsConfig `json:"metrics_config,omitempty"`
	PipelineConfig *appsynctypes.PipelineConfig            `json:"pipeline_config,omitempty"`
	ResolverArn    *string                                 `json:"resolver_arn,omitempty"`
	Runtime        *appsynctypes.AppSyncRuntime            `json:"runtime,omitempty"`
	SyncConfig     *appsynctypes.SyncConfig                `json:"sync_config,omitempty"`
	TypeName       *string                                 `json:"type_name,omitempty"`
}

func sanitizedResolvers(resolvers []appsynctypes.Resolver) []sanitizedResolver {
	result := make([]sanitizedResolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		result = append(result, sanitizedResolver{
			CachingConfig:  resolver.CachingConfig,
			DataSourceName: resolver.DataSourceName,
			FieldName:      resolver.FieldName,
			Kind:           resolver.Kind,
			MaxBatchSize:   resolver.MaxBatchSize,
			MetricsConfig:  resolver.MetricsConfig,
			PipelineConfig: resolver.PipelineConfig,
			ResolverArn:    resolver.ResolverArn,
			Runtime:        resolver.Runtime,
			SyncConfig:     resolver.SyncConfig,
			TypeName:       resolver.TypeName,
		})
	}
	return result
}

func additionalAuthTypes(api appsynctypes.GraphqlApi) []string {
	values := make([]string, 0, len(api.AdditionalAuthenticationProviders))
	for _, provider := range api.AdditionalAuthenticationProviders {
		values = append(values, string(provider.AuthenticationType))
	}
	return sortedUniqueStrings(values)
}

func authorizationModes(api appsynctypes.GraphqlApi) []string {
	values := []string{string(api.AuthenticationType)}
	for _, provider := range api.AdditionalAuthenticationProviders {
		values = append(values, string(provider.AuthenticationType))
	}
	return sortedUniqueStrings(values)
}

func dataSourceNames(dataSources []appsynctypes.DataSource) []string {
	values := make([]string, 0, len(dataSources))
	for _, dataSource := range dataSources {
		values = append(values, awssdk.ToString(dataSource.Name))
	}
	return sortedUniqueStrings(values)
}

func dataSourceTypes(dataSources []appsynctypes.DataSource) []string {
	values := make([]string, 0, len(dataSources))
	for _, dataSource := range dataSources {
		values = append(values, string(dataSource.Type))
	}
	return sortedUniqueStrings(values)
}

func dataSourceRoleARNs(dataSources []appsynctypes.DataSource) []string {
	values := make([]string, 0, len(dataSources))
	for _, dataSource := range dataSources {
		values = append(values, awssdk.ToString(dataSource.ServiceRoleArn))
	}
	return sortedUniqueStrings(values)
}

func typeNames(types []appsynctypes.Type) []string {
	values := make([]string, 0, len(types))
	for _, graphType := range types {
		values = append(values, awssdk.ToString(graphType.Name))
	}
	return sortedUniqueStrings(values)
}

func resolverKinds(resolvers []appsynctypes.Resolver) []string {
	values := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		values = append(values, string(resolver.Kind))
	}
	return sortedUniqueStrings(values)
}

func resolverDataSourceNames(resolvers []appsynctypes.Resolver) []string {
	values := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		values = append(values, awssdk.ToString(resolver.DataSourceName))
	}
	return sortedUniqueStrings(values)
}

func resolverFields(resolvers []appsynctypes.Resolver) []string {
	values := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		typeName := awssdk.ToString(resolver.TypeName)
		fieldName := awssdk.ToString(resolver.FieldName)
		if typeName != "" && fieldName != "" {
			values = append(values, typeName+"."+fieldName)
			continue
		}
		values = append(values, fieldName)
	}
	return sortedUniqueStrings(values)
}

func endpoint(api appsynctypes.GraphqlApi, key string) string {
	return firstNonEmpty(api.Uris[key], api.Uris[strings.ToLower(key)], api.Dns[key], api.Dns[strings.ToLower(key)])
}

func additionalUserPoolConfig(api appsynctypes.GraphqlApi) *appsynctypes.CognitoUserPoolConfig {
	for _, provider := range api.AdditionalAuthenticationProviders {
		if provider.UserPoolConfig != nil {
			return provider.UserPoolConfig
		}
	}
	return nil
}

func openIDConnectConfig(api appsynctypes.GraphqlApi) *appsynctypes.OpenIDConnectConfig {
	if api.OpenIDConnectConfig != nil {
		return api.OpenIDConnectConfig
	}
	for _, provider := range api.AdditionalAuthenticationProviders {
		if provider.OpenIDConnectConfig != nil {
			return provider.OpenIDConnectConfig
		}
	}
	return nil
}

func lambdaAuthorizerConfig(api appsynctypes.GraphqlApi) *appsynctypes.LambdaAuthorizerConfig {
	if api.LambdaAuthorizerConfig != nil {
		return api.LambdaAuthorizerConfig
	}
	for _, provider := range api.AdditionalAuthenticationProviders {
		if provider.LambdaAuthorizerConfig != nil {
			return provider.LambdaAuthorizerConfig
		}
	}
	return nil
}

func commonCloudAssetAttributes(settings Settings, resourceID string, resourceName string, tags map[string]string) map[string]string {
	env := tagLookup(tags, "environment", "env", "stage")
	return map[string]string{
		"domain":            settings.AccountID,
		"env":               env,
		"environment":       env,
		"family":            "appsync_graphql_api",
		"owner":             tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"region":            settings.Region,
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "aws",
		"resource_type":     "appsync_graphql_api",
		"tags":              encodeTags(tags),
		"team":              tagLookup(tags, "team", "squad", "group"),
	}
}

func putAttributes(attributes map[string]string, values map[string]string) {
	for key, value := range values {
		attributes[key] = value
	}
}

func sortedUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func tagLookup(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}
	for _, key := range keys {
		for tagKey, value := range tags {
			if strings.EqualFold(strings.TrimSpace(tagKey), key) && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}
