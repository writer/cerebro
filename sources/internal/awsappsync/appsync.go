package awsappsync

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

type GraphQLAPI struct {
	appsynctypes.GraphqlApi `json:"api"`
	DataSources             []appsynctypes.DataSource `json:"data_sources,omitempty"`
	Types                   []appsynctypes.Type       `json:"types,omitempty"`
	Resolvers               []appsynctypes.Resolver   `json:"resolvers,omitempty"`
	Tags                    map[string]string         `json:"tags,omitempty"`
}

type Client interface {
	ListGraphqlApis(context.Context, *appsync.ListGraphqlApisInput, ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
	ListDataSources(context.Context, *appsync.ListDataSourcesInput, ...func(*appsync.Options)) (*appsync.ListDataSourcesOutput, error)
	ListResolvers(context.Context, *appsync.ListResolversInput, ...func(*appsync.Options)) (*appsync.ListResolversOutput, error)
	ListTagsForResource(context.Context, *appsync.ListTagsForResourceInput, ...func(*appsync.Options)) (*appsync.ListTagsForResourceOutput, error)
	ListTypes(context.Context, *appsync.ListTypesInput, ...func(*appsync.Options)) (*appsync.ListTypesOutput, error)
}

type Settings struct {
	AccountID string
	Region    string
}

func NewClient(cfg awssdk.Config) Client { return appsync.NewFromConfig(cfg) }

func List(ctx context.Context, client Client, cursor string, pageSize int32) ([]GraphQLAPI, string, error) {
	out, err := client.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{MaxResults: pageSize, NextToken: stringPtr(cursor)})
	if err != nil {
		return nil, "", err
	}
	records := make([]GraphQLAPI, 0, len(out.GraphqlApis))
	for _, api := range out.GraphqlApis {
		record := GraphQLAPI{GraphqlApi: api}
		apiID := awssdk.ToString(api.ApiId)
		arn := awssdk.ToString(api.Arn)
		if arn != "" {
			tags, err := client.ListTagsForResource(ctx, &appsync.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", err
			}
			record.Tags = tags.Tags
		}
		if apiID != "" {
			dataSources, err := listDataSources(ctx, client, apiID, pageSize)
			if err != nil {
				return nil, "", err
			}
			record.DataSources = dataSources
			types, err := listTypes(ctx, client, apiID, pageSize)
			if err != nil {
				return nil, "", err
			}
			record.Types = types
			resolvers, err := listResolvers(ctx, client, apiID, types, pageSize)
			if err != nil {
				return nil, "", err
			}
			record.Resolvers = resolvers
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listDataSources(ctx context.Context, client Client, apiID string, pageSize int32) ([]appsynctypes.DataSource, error) {
	var records []appsynctypes.DataSource
	var nextToken *string
	seen := map[string]bool{}
	for {
		out, err := client.ListDataSources(ctx, &appsync.ListDataSourcesInput{ApiId: awssdk.String(apiID), MaxResults: pageSize, NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		records = append(records, out.DataSources...)
		token := awssdk.ToString(out.NextToken)
		if token == "" {
			return records, nil
		}
		if seen[token] {
			return nil, fmt.Errorf("appsync data source pagination repeated token for api %q", apiID)
		}
		seen[token] = true
		nextToken = out.NextToken
	}
}

func listTypes(ctx context.Context, client Client, apiID string, pageSize int32) ([]appsynctypes.Type, error) {
	var records []appsynctypes.Type
	var nextToken *string
	seen := map[string]bool{}
	for {
		out, err := client.ListTypes(ctx, &appsync.ListTypesInput{ApiId: awssdk.String(apiID), Format: appsynctypes.TypeDefinitionFormatJson, MaxResults: pageSize, NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		records = append(records, out.Types...)
		token := awssdk.ToString(out.NextToken)
		if token == "" {
			return records, nil
		}
		if seen[token] {
			return nil, fmt.Errorf("appsync type pagination repeated token for api %q", apiID)
		}
		seen[token] = true
		nextToken = out.NextToken
	}
}

func listResolvers(ctx context.Context, client Client, apiID string, types []appsynctypes.Type, pageSize int32) ([]appsynctypes.Resolver, error) {
	var records []appsynctypes.Resolver
	for _, graphType := range types {
		typeName := awssdk.ToString(graphType.Name)
		if typeName == "" {
			continue
		}
		var nextToken *string
		seen := map[string]bool{}
		for {
			out, err := client.ListResolvers(ctx, &appsync.ListResolversInput{ApiId: awssdk.String(apiID), TypeName: awssdk.String(typeName), MaxResults: pageSize, NextToken: nextToken})
			if err != nil {
				return nil, err
			}
			records = append(records, out.Resolvers...)
			token := awssdk.ToString(out.NextToken)
			if token == "" {
				break
			}
			if seen[token] {
				return nil, fmt.Errorf("appsync resolver pagination repeated token for api %q type %q", apiID, typeName)
			}
			seen[token] = true
			nextToken = out.NextToken
		}
	}
	return records, nil
}

func Event(settings Settings, api GraphQLAPI, occurredAt time.Time) (*primitives.Event, error) {
	payload, attributes, id, err := EventData(settings, api)
	if err != nil {
		return nil, err
	}
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: settings.AccountID, SourceId: "aws", Kind: "aws.appsync_graphql_api", OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: "aws/appsync_graphql_api/v1", Payload: payload, Attributes: attributes}, nil
}

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

func firstTags(values ...map[string]string) map[string]string {
	for _, tags := range values {
		if len(tags) > 0 {
			return tags
		}
	}
	return nil
}

func encodeTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+tags[key])
	}
	return strings.Join(pairs, ",")
}

func resourceName(arn string) string {
	if trimmed := strings.TrimSpace(arn); trimmed != "" {
		parts := strings.Split(trimmed, "/")
		return parts[len(parts)-1]
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func boolString(value bool) string { return strconv.FormatBool(value) }

func stringPtr(value string) *string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return &trimmed
	}
	return nil
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}
