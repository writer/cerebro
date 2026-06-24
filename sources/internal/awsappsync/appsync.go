package awsappsync

import (
	"context"
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
