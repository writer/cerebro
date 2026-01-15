package agents

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// awsInspect executes read-only AWS commands to verify infrastructure state
func (st *SecurityTools) awsInspect(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Service string          `json:"service"`
		Action  string          `json:"action"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	// Load AWS config (uses environment variables or shared config profile)
	// We load it per request to pick up any environment changes, but in prod could be cached
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	switch params.Service {
	case "s3":
		return st.handleS3(ctx, cfg, params.Action, params.Params)
	case "lambda":
		return st.handleLambda(ctx, cfg, params.Action, params.Params)
	case "ecs":
		return st.handleECS(ctx, cfg, params.Action, params.Params)
	case "iam":
		return st.handleIAM(ctx, cfg, params.Action, params.Params)
	default:
		return "", fmt.Errorf("unsupported service: %s", params.Service)
	}
}

func (st *SecurityTools) handleS3(ctx context.Context, cfg aws.Config, action string, args json.RawMessage) (string, error) {
	client := s3.NewFromConfig(cfg)

	switch action {
	case "list-buckets":
		result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return "", err
		}
		return toJSON(result.Buckets)
	case "list-objects":
		var input s3.ListObjectsV2Input
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.ListObjectsV2(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.Contents)
	default:
		return "", fmt.Errorf("unsupported s3 action: %s", action)
	}
}

func (st *SecurityTools) handleLambda(ctx context.Context, cfg aws.Config, action string, args json.RawMessage) (string, error) {
	client := lambda.NewFromConfig(cfg)

	switch action {
	case "list-functions":
		result, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
		if err != nil {
			return "", err
		}
		return toJSON(result.Functions)
	case "get-function":
		var input lambda.GetFunctionInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetFunction(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	default:
		return "", fmt.Errorf("unsupported lambda action: %s", action)
	}
}

func (st *SecurityTools) handleECS(ctx context.Context, cfg aws.Config, action string, args json.RawMessage) (string, error) {
	client := ecs.NewFromConfig(cfg)

	switch action {
	case "list-clusters":
		result, err := client.ListClusters(ctx, &ecs.ListClustersInput{})
		if err != nil {
			return "", err
		}
		return toJSON(result.ClusterArns)
	case "list-services":
		var input ecs.ListServicesInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.ListServices(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.ServiceArns)
	default:
		return "", fmt.Errorf("unsupported ecs action: %s", action)
	}
}

func (st *SecurityTools) handleIAM(ctx context.Context, cfg aws.Config, action string, args json.RawMessage) (string, error) {
	client := iam.NewFromConfig(cfg)

	switch action {
	case "list-roles":
		result, err := client.ListRoles(ctx, &iam.ListRolesInput{})
		if err != nil {
			return "", err
		}
		return toJSON(result.Roles)
	default:
		return "", fmt.Errorf("unsupported iam action: %s", action)
	}
}

func toJSON(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
