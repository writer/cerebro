package awsappsync

import (
	"context"
	"encoding/json"
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

type GraphQLAPI = appsynctypes.GraphqlApi

type Client interface {
	ListGraphqlApis(context.Context, *appsync.ListGraphqlApisInput, ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
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
	return out.GraphqlApis, awssdk.ToString(out.NextToken), nil
}

func Event(settings Settings, api GraphQLAPI, occurredAt time.Time) (*primitives.Event, error) {
	payload, attributes, id, err := EventData(settings, api)
	if err != nil {
		return nil, err
	}
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: settings.AccountID, SourceId: "aws", Kind: "aws.appsync_graphql_api", OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: "aws/appsync_graphql_api/v1", Payload: payload, Attributes: attributes}, nil
}

func EventData(settings Settings, api appsynctypes.GraphqlApi) ([]byte, map[string]string, string, error) {
	arn := awssdk.ToString(api.Arn)
	apiID := awssdk.ToString(api.ApiId)
	name := firstNonEmpty(awssdk.ToString(api.Name), resourceName(arn), apiID)
	attributes := commonCloudAssetAttributes(settings, firstNonEmpty(arn, apiID, name), name, api.Tags)
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
	payload, err := json.Marshal(map[string]any{"account_id": settings.AccountID, "region": settings.Region, "api": api})
	return payload, attributes, "aws-appsync-graphql-api-" + firstNonEmpty(arn, apiID, name), err
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
