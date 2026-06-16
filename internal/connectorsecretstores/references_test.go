package connectorsecretstores

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/writer/cerebro/internal/config"
)

type fakeAWSSecretsManager struct {
	secretID string
	value    string
}

func (f *fakeAWSSecretsManager) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.secretID = awssdk.ToString(input.SecretId)
	return &secretsmanager.GetSecretValueOutput{SecretString: awssdk.String(f.value)}, nil
}

func TestParseAWSReferenceWithRegionAndJSONField(t *testing.T) {
	ref, ok, err := ParseReference("aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#secret_access_key")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	if !ok {
		t.Fatal("ParseReference() ok = false, want true")
	}
	if ref.StoreID != StoreAWSSecretsManager || ref.Region != "us-east-1" || ref.SecretID != "cerebro/tenant-a/aws/runtime-a/credentials" || ref.Field != "secret_access_key" {
		t.Fatalf("reference = %#v, want parsed AWS reference", ref)
	}
}

func TestParseAWSReferenceKeepsARNSecretID(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-west-2:123456789012:secret:cerebro/aws/runtime-AbCd"
	ref, ok, err := ParseReference("aws-sm:" + arn + "#value")
	if err != nil {
		t.Fatalf("ParseReference() error = %v", err)
	}
	if !ok {
		t.Fatal("ParseReference() ok = false, want true")
	}
	if ref.Region != "us-west-2" || ref.SecretID != arn || ref.Field != "value" {
		t.Fatalf("reference = %#v, want ARN secret id and region", ref)
	}
}

func TestResolverResolvesAWSSecretJSONField(t *testing.T) {
	fake := &fakeAWSSecretsManager{value: `{"value":"resolved-value","ttl":3600}`}
	resolver := NewResolver(config.ConnectorSecretStoreConfig{
		Enabled: []string{StoreAWSSecretsManager},
		AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
			Region: "us-east-1",
		},
	})
	resolver.awsClientFactory = func(context.Context, config.AWSSecretsManagerStoreConfig, Reference) (awsSecretsManagerAPI, error) {
		return fake, nil
	}

	resolved, err := resolver.ResolveReferences(context.Background(), map[string]string{
		"value": "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#value",
		"env":   "env:CEREBRO_SOURCE_AWS_VALUE",
	})
	if err != nil {
		t.Fatalf("ResolveReferences() error = %v", err)
	}
	if resolved["value"] != "resolved-value" {
		t.Fatalf("resolved value = %q, want resolved-value", resolved["value"])
	}
	if resolved["env"] != "env:CEREBRO_SOURCE_AWS_VALUE" {
		t.Fatalf("env reference = %q, want unchanged env reference", resolved["env"])
	}
	if fake.secretID != "cerebro/tenant-a/aws/runtime-a/credentials" {
		t.Fatalf("fake secret id = %q, want scoped runtime secret id", fake.secretID)
	}
}

func TestResolverPreservesAWSSecretJSONNumberField(t *testing.T) {
	fake := &fakeAWSSecretsManager{value: `{"account_id":123456789012}`}
	resolver := NewResolver(config.ConnectorSecretStoreConfig{
		Enabled: []string{StoreAWSSecretsManager},
		AWSSecretsManager: config.AWSSecretsManagerStoreConfig{
			Region: "us-east-1",
		},
	})
	resolver.awsClientFactory = func(context.Context, config.AWSSecretsManagerStoreConfig, Reference) (awsSecretsManagerAPI, error) {
		return fake, nil
	}

	resolved, err := resolver.ResolveReferences(context.Background(), map[string]string{
		"account_id": "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#account_id",
	})
	if err != nil {
		t.Fatalf("ResolveReferences() error = %v", err)
	}
	if resolved["account_id"] != "123456789012" {
		t.Fatalf("resolved account_id = %q, want exact JSON number literal", resolved["account_id"])
	}
}

func TestResolverRejectsDisabledNativeStore(t *testing.T) {
	resolver := NewResolver(config.ConnectorSecretStoreConfig{})
	_, err := resolver.ResolveReferences(context.Background(), map[string]string{
		"value": "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#value",
	})
	if err == nil {
		t.Fatal("ResolveReferences() error = nil, want disabled store error")
	}
}

func TestResolverRequiresConfiguredAWSRegionForNativeReferences(t *testing.T) {
	resolver := NewResolver(config.ConnectorSecretStoreConfig{
		Enabled: []string{StoreAWSSecretsManager},
	})
	_, err := resolver.ResolveReferences(context.Background(), map[string]string{
		"value": "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#value",
	})
	if err == nil {
		t.Fatal("ResolveReferences() error = nil, want resolver unavailable without configured region")
	}
}

func TestAuthorizeRuntimeReferencesRequiresScopedAWSSecret(t *testing.T) {
	err := AuthorizeRuntimeReferences("aws", "tenant-a", "runtime-a", map[string]string{
		"value": "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#value",
	})
	if err != nil {
		t.Fatalf("AuthorizeRuntimeReferences(scoped) error = %v", err)
	}

	err = AuthorizeRuntimeReferences("aws", "tenant-a", "runtime-a", map[string]string{
		"value": "aws-sm:us-east-1:shared/credentials#value",
	})
	if err == nil {
		t.Fatal("AuthorizeRuntimeReferences(unscoped) error = nil, want invalid reference")
	}
}

func TestAuthorizeRuntimeReferencesRejectsNonCanonicalRuntimeScope(t *testing.T) {
	if got := RuntimeSecretPrefix("prod/aws", "aws", "runtime-a"); got != "" {
		t.Fatalf("RuntimeSecretPrefix(unsafe tenant) = %q, want empty", got)
	}
	if got := RuntimeSecretPrefix("prod_aws", "aws", "runtime-a"); got != "cerebro/prod_aws/aws/runtime-a/" {
		t.Fatalf("RuntimeSecretPrefix(canonical tenant) = %q, want canonical prefix", got)
	}
	err := AuthorizeRuntimeReferences("aws", "prod/aws", "runtime-a", map[string]string{
		"value": "aws-sm:us-east-1:cerebro/prod_aws/aws/runtime-a/credentials#value",
	})
	if err == nil {
		t.Fatal("AuthorizeRuntimeReferences(non-canonical tenant) error = nil, want invalid reference")
	}
}

func TestAuthorizeRuntimeReferencesAcceptsScopedAWSARN(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-west-2:123456789012:secret:cerebro/tenant-a/aws/runtime-a/credentials-AbCd"
	err := AuthorizeRuntimeReferences("aws", "tenant-a", "runtime-a", map[string]string{
		"value": "aws-sm:" + arn + "#value",
	})
	if err != nil {
		t.Fatalf("AuthorizeRuntimeReferences(arn) error = %v", err)
	}
}

func TestValidateReferenceForStoreRejectsMismatchedPrefix(t *testing.T) {
	if err := ValidateReferenceForStore(StoreInfisical, "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#value"); err == nil {
		t.Fatal("ValidateReferenceForStore() error = nil, want mismatch error")
	}
	if err := ValidateReferenceForStore(StoreInfisical, "env:CEREBRO_SOURCE_AWS_VALUE"); err != nil {
		t.Fatalf("ValidateReferenceForStore(env) error = %v", err)
	}
}

func TestValidateReferenceForStoreRejectsUnsupportedNativePrefix(t *testing.T) {
	if err := ValidateReferenceForStore(StoreInfisical, "infisical:/cerebro/tenant-a/aws/runtime-a/credentials#value"); err == nil {
		t.Fatal("ValidateReferenceForStore(infisical native) error = nil, want unsupported native prefix")
	}
	if got := ReferencePrefixes(StoreInfisical); len(got) != 1 || got[0] != "env:" {
		t.Fatalf("ReferencePrefixes(infisical) = %#v, want env only", got)
	}
}
