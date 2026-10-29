package cloudidentitysource

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

// gcpCloudPlatformScope matches the scope used by the existing GCP source's
// workload-identity-federation token exchange (sources/gcp/source.go).
const gcpCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// NewGCPCredentialSource builds an oauth2.TokenSource via AWS-to-GCP Workload
// Identity Federation, reusing the same externalaccount.NewTokenSource pattern
// as the existing GCP source (sources/gcp/source.go defaultGCPTokenSource).
// It takes an already-constructed aws.Config instead of loading one itself, so
// this reader performs no environment or credential-file reads of its own; the
// caller (Source config/wrapper layer) is responsible for building awsConfig
// the same way it already does for every other AWS-config-consuming reader.
//
// This is narrow sugar: callers may also inject any other oauth2.TokenSource
// (e.g. application default credentials, a static token) directly into
// GCPOptions.TokenSource without using this factory at all.
func NewGCPCredentialSource(ctx context.Context, awsConfig awssdk.Config, audience string, serviceAccount string) (oauth2.TokenSource, error) {
	audience = strings.TrimSpace(audience)
	serviceAccount = strings.TrimSpace(serviceAccount)
	if audience == "" {
		return nil, fmt.Errorf("cloudidentitysource: GCP credential source requires a workload identity audience")
	}
	if serviceAccount == "" {
		return nil, fmt.Errorf("cloudidentitysource: GCP credential source requires a service account to impersonate")
	}
	region := strings.TrimSpace(awsConfig.Region)
	if region == "" {
		return nil, fmt.Errorf("cloudidentitysource: GCP credential source requires an AWS region on the injected config")
	}
	return externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience:                       audience,
		SubjectTokenType:               "urn:ietf:params:aws:token-type:aws4_request",
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(serviceAccount) + ":generateAccessToken",
		Scopes:                         []string{gcpCloudPlatformScope},
		AwsSecurityCredentialsSupplier: gcpAWSCredentialsSupplier{region: region, config: awsConfig},
	})
}

// gcpAWSCredentialsSupplier mirrors sources/gcp/source.go's awsCredentialsSupplier.
type gcpAWSCredentialsSupplier struct {
	region string
	config awssdk.Config
}

func (s gcpAWSCredentialsSupplier) AwsRegion(context.Context, externalaccount.SupplierOptions) (string, error) {
	return s.region, nil
}

func (s gcpAWSCredentialsSupplier) AwsSecurityCredentials(ctx context.Context, _ externalaccount.SupplierOptions) (*externalaccount.AwsSecurityCredentials, error) {
	credentials, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("cloudidentitysource: retrieve aws credentials for gcp workload identity federation: %w", err)
	}
	return &externalaccount.AwsSecurityCredentials{
		AccessKeyID:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
	}, nil
}
