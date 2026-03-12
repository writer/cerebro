package functionscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type awsLambdaAPI interface {
	GetFunction(ctx context.Context, params *lambda.GetFunctionInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
	GetLayerVersionByArn(ctx context.Context, params *lambda.GetLayerVersionByArnInput, optFns ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error)
}

type AWSProvider struct {
	client     awsLambdaAPI
	httpClient *http.Client
}

func NewAWSProvider(ctx context.Context, region string) (*AWSProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(strings.TrimSpace(region)))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return NewAWSProviderWithClient(lambda.NewFromConfig(cfg)), nil
}

func NewAWSProviderWithClient(client awsLambdaAPI) *AWSProvider {
	return &AWSProvider{client: client, httpClient: &http.Client{Timeout: 2 * time.Minute}}
}

func (p *AWSProvider) Kind() ProviderKind { return ProviderAWS }

func (p *AWSProvider) DescribeFunction(ctx context.Context, target FunctionTarget) (*FunctionDescriptor, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws function scan provider is not configured")
	}
	functionID := strings.TrimSpace(target.FunctionARN)
	if functionID == "" {
		functionID = strings.TrimSpace(target.FunctionName)
	}
	if functionID == "" {
		return nil, fmt.Errorf("aws function name or arn is required")
	}
	out, err := p.client.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(functionID)})
	if err != nil {
		return nil, fmt.Errorf("get lambda function %s: %w", functionID, err)
	}
	config := out.Configuration
	if config == nil {
		return nil, fmt.Errorf("lambda returned empty configuration for %s", functionID)
	}
	descriptor := &FunctionDescriptor{
		ID:             strings.TrimSpace(aws.ToString(config.FunctionArn)),
		Name:           strings.TrimSpace(aws.ToString(config.FunctionName)),
		Runtime:        string(config.Runtime),
		EntryPoint:     strings.TrimSpace(aws.ToString(config.Handler)),
		PackageType:    string(config.PackageType),
		CodeSHA256:     strings.TrimSpace(aws.ToString(config.CodeSha256)),
		CodeSize:       config.CodeSize,
		Role:           strings.TrimSpace(aws.ToString(config.Role)),
		TimeoutSeconds: aws.ToInt32(config.Timeout),
		MemoryMB:       int64(aws.ToInt32(config.MemorySize)),
		Metadata: map[string]any{
			"last_modified": strings.TrimSpace(aws.ToString(config.LastModified)),
		},
	}
	if config.LastModified != nil && strings.TrimSpace(aws.ToString(config.LastModified)) != "" {
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(aws.ToString(config.LastModified))); err == nil {
			ts = ts.UTC()
			descriptor.UpdatedAt = &ts
		}
	}
	if len(config.Architectures) > 0 {
		descriptor.Architectures = make([]string, 0, len(config.Architectures))
		for _, arch := range config.Architectures {
			descriptor.Architectures = append(descriptor.Architectures, string(arch))
		}
	}
	if config.Environment != nil && len(config.Environment.Variables) > 0 {
		descriptor.Environment = cloneStringMap(config.Environment.Variables)
	}
	if config.VpcConfig != nil {
		descriptor.VpcConfig = map[string]any{
			"subnet_ids":         cloneStringSlice(config.VpcConfig.SubnetIds),
			"security_group_ids": cloneStringSlice(config.VpcConfig.SecurityGroupIds),
			"ipv6_allowed":       aws.ToBool(config.VpcConfig.Ipv6AllowedForDualStack),
		}
	}
	if out.Code != nil {
		descriptor.ImageURI = strings.TrimSpace(aws.ToString(out.Code.ImageUri))
	}
	for _, layer := range config.Layers {
		layerARN := strings.TrimSpace(aws.ToString(layer.Arn))
		if layerARN == "" {
			continue
		}
		descriptor.Layers = append(descriptor.Layers, FunctionLayer{
			ARN:      layerARN,
			CodeSize: layer.CodeSize,
			Metadata: map[string]any{"signing_profile_version_arn": strings.TrimSpace(aws.ToString(layer.SigningProfileVersionArn))},
		})
		descriptor.Artifacts = append(descriptor.Artifacts, ArtifactRef{
			ID:     layerARN,
			Kind:   ArtifactLayer,
			Format: ArchiveFormatZIP,
			Name:   layerARN,
			Size:   layer.CodeSize,
		})
	}
	if descriptor.PackageType == string(lambdatypes.PackageTypeZip) {
		descriptor.Artifacts = append(descriptor.Artifacts, ArtifactRef{
			ID:     "function_code",
			Kind:   ArtifactFunctionCode,
			Format: ArchiveFormatZIP,
			Name:   descriptor.Name + ".zip",
			Size:   descriptor.CodeSize,
		})
	}
	if descriptor.ID == "" {
		descriptor.ID = functionID
	}
	if descriptor.Name == "" {
		descriptor.Name = functionID
	}
	return descriptor, nil
}

func (p *AWSProvider) OpenArtifact(ctx context.Context, target FunctionTarget, artifact ArtifactRef) (io.ReadCloser, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("aws function scan provider is not configured")
	}
	var downloadURL string
	switch artifact.Kind {
	case ArtifactFunctionCode:
		functionID := strings.TrimSpace(target.FunctionARN)
		if functionID == "" {
			functionID = strings.TrimSpace(target.FunctionName)
		}
		out, err := p.client.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(functionID)})
		if err != nil {
			return nil, fmt.Errorf("get lambda function package %s: %w", functionID, err)
		}
		if out.Code == nil {
			return nil, fmt.Errorf("lambda function %s does not expose downloadable code metadata", functionID)
		}
		downloadURL = strings.TrimSpace(aws.ToString(out.Code.Location))
	case ArtifactLayer:
		out, err := p.client.GetLayerVersionByArn(ctx, &lambda.GetLayerVersionByArnInput{Arn: aws.String(strings.TrimSpace(artifact.ID))})
		if err != nil {
			return nil, fmt.Errorf("get lambda layer %s: %w", artifact.ID, err)
		}
		if out.Content == nil {
			return nil, fmt.Errorf("lambda layer %s does not expose downloadable content metadata", artifact.ID)
		}
		downloadURL = strings.TrimSpace(aws.ToString(out.Content.Location))
	default:
		return nil, fmt.Errorf("unsupported aws function artifact kind %s", artifact.Kind)
	}
	return openHTTPArtifact(ctx, p.httpClient, downloadURL)
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(value))
	}
	return out
}
