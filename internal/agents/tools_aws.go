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

var awsSupportedServices = []string{"s3", "lambda", "ecs", "iam"}

var s3SupportedActions = []string{
	"list-buckets",
	"list-objects",
	"get-bucket-acl",
	"get-bucket-policy",
	"get-public-access-block",
	"get-bucket-encryption",
	"get-bucket-location",
	"get-bucket-versioning",
	"get-bucket-logging",
	"get-bucket-policy-status",
}

var lambdaSupportedActions = []string{
	"list-functions",
	"get-function",
	"get-function-configuration",
	"get-policy",
}

var ecsSupportedActions = []string{
	"list-clusters",
	"list-services",
	"describe-clusters",
	"describe-services",
	"describe-task-definition",
}

var iamSupportedActions = []string{
	"list-roles",
	"get-role",
	"list-attached-role-policies",
	"list-role-policies",
	"get-policy",
}

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

	if !containsString(awsSupportedServices, params.Service) {
		return "", UnsupportedServiceError("aws", params.Service, awsSupportedServices)
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
		return "", UnsupportedServiceError("aws", params.Service, awsSupportedServices)
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
	case "get-bucket-acl":
		var input s3.GetBucketAclInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketAcl(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-policy":
		var input s3.GetBucketPolicyInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketPolicy(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-public-access-block":
		var input s3.GetPublicAccessBlockInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetPublicAccessBlock(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-encryption":
		var input s3.GetBucketEncryptionInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketEncryption(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-location":
		var input s3.GetBucketLocationInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketLocation(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-versioning":
		var input s3.GetBucketVersioningInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketVersioning(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-logging":
		var input s3.GetBucketLoggingInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketLogging(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-bucket-policy-status":
		var input s3.GetBucketPolicyStatusInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetBucketPolicyStatus(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	default:
		return "", UnsupportedActionError("s3", action, s3SupportedActions)
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
	case "get-function-configuration":
		var input lambda.GetFunctionConfigurationInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetFunctionConfiguration(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	case "get-policy":
		var input lambda.GetPolicyInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetPolicy(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result)
	default:
		return "", UnsupportedActionError("lambda", action, lambdaSupportedActions)
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
	case "describe-clusters":
		var input ecs.DescribeClustersInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.DescribeClusters(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.Clusters)
	case "describe-services":
		var input ecs.DescribeServicesInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.DescribeServices(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.Services)
	case "describe-task-definition":
		var input ecs.DescribeTaskDefinitionInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.DescribeTaskDefinition(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.TaskDefinition)
	default:
		return "", UnsupportedActionError("ecs", action, ecsSupportedActions)
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
	case "get-role":
		var input iam.GetRoleInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetRole(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.Role)
	case "list-attached-role-policies":
		var input iam.ListAttachedRolePoliciesInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.ListAttachedRolePolicies(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.AttachedPolicies)
	case "list-role-policies":
		var input iam.ListRolePoliciesInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.ListRolePolicies(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.PolicyNames)
	case "get-policy":
		var input iam.GetPolicyInput
		if err := json.Unmarshal(args, &input); err != nil {
			return "", err
		}
		result, err := client.GetPolicy(ctx, &input)
		if err != nil {
			return "", err
		}
		return toJSON(result.Policy)
	default:
		return "", UnsupportedActionError("iam", action, iamSupportedActions)
	}
}

func toJSON(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
