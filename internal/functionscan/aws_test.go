package functionscan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type fakeAWSLambdaClient struct {
	getFunction          func(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
	getLayerVersionByArn func(context.Context, *lambda.GetLayerVersionByArnInput, ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error)
}

func (f *fakeAWSLambdaClient) GetFunction(ctx context.Context, input *lambda.GetFunctionInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	if f.getFunction != nil {
		return f.getFunction(ctx, input, optFns...)
	}
	return &lambda.GetFunctionOutput{}, nil
}

func (f *fakeAWSLambdaClient) GetLayerVersionByArn(ctx context.Context, input *lambda.GetLayerVersionByArnInput, optFns ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error) {
	if f.getLayerVersionByArn != nil {
		return f.getLayerVersionByArn(ctx, input, optFns...)
	}
	return &lambda.GetLayerVersionByArnOutput{}, nil
}

func TestAWSProviderOpenArtifactRejectsMissingFunctionCodeMetadata(t *testing.T) {
	provider := NewAWSProviderWithClient(&fakeAWSLambdaClient{
		getFunction: func(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
			return &lambda.GetFunctionOutput{}, nil
		},
	})

	_, err := provider.OpenArtifact(context.Background(), FunctionTarget{Provider: ProviderAWS, FunctionName: "demo"}, ArtifactRef{
		ID:     "function_code",
		Kind:   ArtifactFunctionCode,
		Format: ArchiveFormatZIP,
	})
	if err == nil || !strings.Contains(err.Error(), "downloadable code metadata") {
		t.Fatalf("expected missing code metadata error, got %v", err)
	}
}

func TestAWSProviderOpenArtifactRejectsMissingLayerContentMetadata(t *testing.T) {
	provider := NewAWSProviderWithClient(&fakeAWSLambdaClient{
		getLayerVersionByArn: func(context.Context, *lambda.GetLayerVersionByArnInput, ...func(*lambda.Options)) (*lambda.GetLayerVersionByArnOutput, error) {
			return &lambda.GetLayerVersionByArnOutput{}, nil
		},
	})

	_, err := provider.OpenArtifact(context.Background(), FunctionTarget{Provider: ProviderAWS, FunctionName: "demo"}, ArtifactRef{
		ID:     "arn:aws:lambda:us-east-1:123456789012:layer:demo:1",
		Kind:   ArtifactLayer,
		Format: ArchiveFormatZIP,
	})
	if err == nil || !strings.Contains(err.Error(), "downloadable content metadata") {
		t.Fatalf("expected missing layer content metadata error, got %v", err)
	}
}

func TestAWSProviderOpenArtifactUsesFunctionCodeLocation(t *testing.T) {
	originalValidator := artifactURLValidator
	artifactURLValidator = func(string) error { return nil }
	defer func() { artifactURLValidator = originalValidator }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "zip-bytes")
	}))
	defer server.Close()

	provider := NewAWSProviderWithClient(&fakeAWSLambdaClient{
		getFunction: func(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
			return &lambda.GetFunctionOutput{
				Code: &lambdatypes.FunctionCodeLocation{
					Location: aws.String(server.URL),
				},
			}, nil
		},
	})
	provider.httpClient = server.Client()

	reader, err := provider.OpenArtifact(context.Background(), FunctionTarget{Provider: ProviderAWS, FunctionName: "demo"}, ArtifactRef{
		ID:     "function_code",
		Kind:   ArtifactFunctionCode,
		Format: ArchiveFormatZIP,
	})
	if err != nil {
		t.Fatalf("open function artifact: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read function artifact: %v", err)
	}
	_ = reader.Close()
	if string(data) != "zip-bytes" {
		t.Fatalf("unexpected artifact payload %q", string(data))
	}
}

func TestAzureRuntimeFromSettingsOmitsEmptyDelimiter(t *testing.T) {
	if got := azureRuntimeFromSettings(map[string]string{"FUNCTIONS_WORKER_RUNTIME": "node"}); got != "node" {
		t.Fatalf("expected bare worker runtime, got %q", got)
	}
	if got := azureRuntimeFromSettings(map[string]string{
		"FUNCTIONS_WORKER_RUNTIME":     "node",
		"WEBSITE_NODE_DEFAULT_VERSION": "16",
	}); got != "node|16" {
		t.Fatalf("expected version-qualified runtime, got %q", got)
	}
}
