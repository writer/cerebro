package cloudidentitysource

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// fakeRoundTripper serves canned JSON bodies keyed by exact request path; it
// never performs a real network call.
type fakeRoundTripper struct {
	responses map[string]string
	calls     []string
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, req.URL.Path)
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("fakeRoundTripper: unexpected method %s", req.Method)
	}
	body, ok := f.responses[req.URL.Path]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte(body))), Header: make(http.Header)}, nil
}

func newTestAWSReaderWithHTTP(t *testing.T, transport http.RoundTripper) *awsReader {
	t.Helper()
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		HTTPClient:       &http.Client{Transport: transport},
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return &fakeIAM{} },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return &fakeEKS{} },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	return readerAny.(*awsReader)
}

// awsTestIndexPath is the real root-index path
// (https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html):
// GET "/" returns [{"service","url"},...]. "/v1/mapping.json" is a distinct,
// SDK-language-keyed document this reader never fetches.
const awsTestIndexPath = "/"

const awsTestMapping = `[{"service":"eks","url":"https://servicereference.us-east-1.amazonaws.com/v1/eks/eks.json"}]`

// awsTestEKSDocument mirrors the real, published shape: Actions[] for the
// identity-policy action/resource-type surface, and a separate Operations[]
// array carrying the actual API-operation-to-authorized-action mapping
// (including a cross-service, conditionally-authorized iam:PassRole
// dependent permission) and per-SDK method aliases, as observed at
// https://servicereference.us-east-1.amazonaws.com/v1/eks/eks.json.
const awsTestEKSDocument = `{
	"Name": "eks",
	"Actions": [
		{"Name": "DescribeCluster", "Resources": [{"Name": "cluster"}]},
		{"Name": "UpdateAddon", "Resources": [{"Name": "cluster"}]}
	],
	"Operations": [
		{
			"Name": "DescribeCluster",
			"AuthorizedActions": [{"Name": "DescribeCluster", "Service": "eks"}],
			"SDK": [{"Name": "eks", "Method": "describe_cluster", "Package": "Boto3"}]
		},
		{
			"Name": "UpdateAddon",
			"AuthorizedActions": [
				{"Name": "PassRole", "Service": "iam", "Context": {"iam:PassedToService": ["eks.amazonaws.com"]}},
				{"Name": "UpdateAddon", "Service": "eks"}
			],
			"SDK": [{"Name": "eks", "Method": "update_addon", "Package": "Boto3"}]
		}
	]
}`

func TestAWSDefineFetchesServiceActionsFromServiceReference(t *testing.T) {
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:   awsTestMapping,
		"/v1/eks/eks.json": awsTestEKSDocument,
	}}
	reader := newTestAWSReaderWithHTTP(t, transport)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"eks"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !definitions.Complete {
		t.Fatalf("expected Complete=true: unresolved dependent-permission exhaustiveness is tracked per-operation via DependenciesComplete, not the top-level flag, gaps=%+v", definitions.Gaps)
	}
	if len(definitions.Actions) != 2 {
		t.Fatalf("expected two parsed actions, got %+v", definitions.Actions)
	}
	foundDescribe := false
	for _, action := range definitions.Actions {
		if action.Name == "eks:DescribeCluster" {
			foundDescribe = true
			if len(action.ResourceTypes) != 1 || action.ResourceTypes[0] != "cluster" {
				t.Fatalf("expected resource type cluster, got %+v", action.ResourceTypes)
			}
		}
	}
	if !foundDescribe {
		t.Fatalf("expected eks:DescribeCluster action, got %+v", definitions.Actions)
	}
	if len(definitions.Operations) != 2 {
		t.Fatalf("expected two operation definitions, got %+v", definitions.Operations)
	}
	var updateAddon *ci.OperationDefinition
	for i := range definitions.Operations {
		if definitions.Operations[i].Operation == "UpdateAddon" {
			updateAddon = &definitions.Operations[i]
		}
	}
	if updateAddon == nil {
		t.Fatalf("expected UpdateAddon operation, got %+v", definitions.Operations)
	}
	if len(updateAddon.Permissions) != 1 || updateAddon.Permissions[0] != "eks:UpdateAddon" {
		t.Fatalf("expected unconditional permission eks:UpdateAddon, got %+v", updateAddon.Permissions)
	}
	if len(updateAddon.ConditionalPermissions) != 1 || updateAddon.ConditionalPermissions[0] != "iam:PassRole" {
		t.Fatalf("expected the context-scoped iam:PassRole to be reported as conditional, not unconditional, got %+v", updateAddon.ConditionalPermissions)
	}
	if len(updateAddon.SDKMethods) != 2 || updateAddon.SDKMethods[0] != "UpdateAddon" || updateAddon.SDKMethods[1] != "update_addon" {
		t.Fatalf("expected the canonical operation name plus the Boto3 method alias, got %+v", updateAddon.SDKMethods)
	}
	if len(updateAddon.SDKServices) != 1 || updateAddon.SDKServices[0] != "eks" {
		t.Fatalf("expected the document's own service namespace in SDKServices, got %+v", updateAddon.SDKServices)
	}
	if updateAddon.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=false: eks:UpdateAddon has no curated profile")
	}
	dependentGapFound := false
	for _, gap := range definitions.Gaps {
		if gap.Code == awsDependentPermissionsIncompleteGapCode && gap.Scope == "eks" {
			dependentGapFound = true
		}
	}
	if !dependentGapFound {
		t.Fatalf("expected the aws_dependent_permissions_incomplete gap scoped to eks, got %+v", definitions.Gaps)
	}

	// A second Define for the same service must reuse the cached fetch
	// (cache within run), not refetch the index/document.
	if _, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"eks"}}); err != nil {
		t.Fatalf("second Define: %v", err)
	}
	if len(transport.calls) != 2 {
		t.Fatalf("expected the service reference fetch to be cached within the run, got calls=%v", transport.calls)
	}
}

func TestAWSDefineServiceWithoutOperationMappingIsScopedGapNotFabricated(t *testing.T) {
	const noOpsDocument = `{"Name":"legacyservice","Actions":[{"Name":"DoThing","Resources":[{"Name":"thing"}]}]}`
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:                       `[{"service":"legacyservice","url":"https://servicereference.us-east-1.amazonaws.com/v1/legacyservice/legacyservice.json"}]`,
		"/v1/legacyservice/legacyservice.json": noOpsDocument,
	}}
	reader := newTestAWSReaderWithHTTP(t, transport)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"legacyservice"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if len(definitions.Actions) != 1 {
		t.Fatalf("expected actions to still resolve, got %+v", definitions.Actions)
	}
	if len(definitions.Operations) != 0 {
		t.Fatalf("expected no fabricated operation mapping, got %+v", definitions.Operations)
	}
	if !definitions.Complete {
		t.Fatalf("expected Complete=true: the action vocabulary fully resolved; missing operation mapping is informational")
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "aws_operation_mapping_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a scoped aws_operation_mapping_unsupported gap, got %+v", definitions.Gaps)
	}
}

func TestAWSDefineOperationWithoutAuthorizedActionsIsUnknownNotZero(t *testing.T) {
	// This operation is published but AWS attached no AuthorizedActions to
	// it (a real, observed shape alongside services with no Operations at
	// all). Its Permissions must read as unknown, never as "requires
	// nothing".
	const document = `{"Name":"partialservice","Actions":[{"Name":"DoThing","Resources":[{"Name":"thing"}]}],"Operations":[{"Name":"DoThing","AuthorizedActions":[],"SDK":[{"Name":"partialservice","Method":"do_thing","Package":"Boto3"}]}]}`
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:                         `[{"service":"partialservice","url":"https://servicereference.us-east-1.amazonaws.com/v1/partialservice/partialservice.json"}]`,
		"/v1/partialservice/partialservice.json": document,
	}}
	reader := newTestAWSReaderWithHTTP(t, transport)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"partialservice"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if len(definitions.Operations) != 1 || len(definitions.Operations[0].Permissions) != 0 {
		t.Fatalf("expected one operation with empty (not fabricated) Permissions, got %+v", definitions.Operations)
	}
	if definitions.Operations[0].DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=false for an operation with no authorized-action data")
	}
	if !definitions.Complete {
		t.Fatalf("expected Complete=true: the action vocabulary resolved; the unresolved operation is tracked via DependenciesComplete and a scoped gap")
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "aws_operation_authorized_actions_unknown" && gap.Scope == "partialservice:DoThing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a scoped aws_operation_authorized_actions_unknown gap, got %+v", definitions.Gaps)
	}
}

func TestAWSDefineExpandsWildcardServiceAgainstLiveIndex(t *testing.T) {
	const mapping = `[{"service":"eks","url":"https://servicereference.us-east-1.amazonaws.com/v1/eks/eks.json"},{"service":"s3","url":"https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json"}]`
	const s3Document = `{"Name":"s3","Actions":[{"Name":"GetObject","Resources":[{"Name":"object"}]}],"Operations":[{"Name":"GetObject","AuthorizedActions":[{"Name":"GetObject","Service":"s3"}],"SDK":[{"Name":"s3","Method":"get_object","Package":"Boto3"}]}]}`
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:   mapping,
		"/v1/eks/eks.json": awsTestEKSDocument,
		"/v1/s3/s3.json":   s3Document,
	}}
	reader := newTestAWSReaderWithHTTP(t, transport)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"*"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !definitions.Complete {
		t.Fatalf("expected Complete=true: informational dependent-permission gaps no longer flip the top-level flag, gaps=%+v", definitions.Gaps)
	}
	if !definitions.AWSServiceCatalogComplete {
		t.Fatalf("expected AWSServiceCatalogComplete=true: a bare \"*\" fully expanded and fetched every indexed service")
	}
	var sawEKS, sawS3 bool
	var getObject *ci.OperationDefinition
	for _, action := range definitions.Actions {
		if action.Name == "eks:DescribeCluster" {
			sawEKS = true
		}
		if action.Name == "s3:GetObject" {
			sawS3 = true
		}
	}
	for i := range definitions.Operations {
		if definitions.Operations[i].Service == "s3" && definitions.Operations[i].Operation == "GetObject" {
			getObject = &definitions.Operations[i]
		}
	}
	if !sawEKS || !sawS3 {
		t.Fatalf("expected the wildcard to expand to every indexed service, got %+v", definitions.Actions)
	}
	if getObject == nil {
		t.Fatalf("expected an s3:GetObject operation definition, got %+v", definitions.Operations)
	}
	if !getObject.DependenciesComplete {
		t.Fatalf("expected the curated s3:GetObject profile to set DependenciesComplete=true, got %+v", getObject)
	}
	for _, want := range []string{"kms:GenerateDataKey", "kms:Decrypt", "s3express:CreateSession"} {
		found := false
		for _, got := range getObject.ConditionalPermissions {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected curated conditional permission %q on s3:GetObject, got %+v", want, getObject.ConditionalPermissions)
		}
	}
}

func TestAWSDefineWildcardBudgetExhaustionIsScopedPartialNotEmpty(t *testing.T) {
	const mapping = `[{"service":"eks","url":"https://servicereference.us-east-1.amazonaws.com/v1/eks/eks.json"},{"service":"s3","url":"https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json"}]`
	const s3Document = `{"Name":"s3","Actions":[{"Name":"GetObject","Resources":[{"Name":"object"}]}],"Operations":[{"Name":"GetObject","AuthorizedActions":[{"Name":"GetObject","Service":"s3"}],"SDK":[{"Name":"s3","Method":"get_object","Package":"Boto3"}]}]}`
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:   mapping,
		"/v1/eks/eks.json": awsTestEKSDocument,
		"/v1/s3/s3.json":   s3Document,
	}}
	// Budget: 1 for the index fetch, 1 for exactly one service document.
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		RequestBudget:    2,
		HTTPClient:       &http.Client{Transport: transport},
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return &fakeIAM{} },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return &fakeEKS{} },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	reader := readerAny.(*awsReader)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"*"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if definitions.Complete {
		t.Fatalf("expected Complete=false once the budget is exhausted mid-wildcard-expansion")
	}
	if definitions.AWSServiceCatalogComplete {
		t.Fatalf("expected AWSServiceCatalogComplete=false: the budget exhausted before every indexed service was fetched")
	}
	if len(definitions.Actions) == 0 {
		t.Fatalf("expected the partially-reached service's actions to survive, not an empty fallback")
	}
	found := false
	for _, gap := range definitions.Gaps {
		if gap.Code == "aws_definitions_wildcard_budget_exhausted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a scoped wildcard-budget gap, got %+v", definitions.Gaps)
	}
}

func TestAWSDefineResolvesManagedPolicyDefaultVersion(t *testing.T) {
	const policyARN = "arn:aws:iam::111111111111:policy/my-policy"
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"PolicyStatement","Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`

	iamFake := &fakeIAM{
		getPolicy: func(in *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			if aws.ToString(in.PolicyArn) != policyARN {
				t.Fatalf("unexpected policy arn: %s", aws.ToString(in.PolicyArn))
			}
			return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v3")}}, nil
		},
		getPolicyVersion: func(in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			if aws.ToString(in.VersionId) != "v3" {
				t.Fatalf("expected the actual default version id to be requested, got %s", aws.ToString(in.VersionId))
			}
			return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(policyDoc)}}, nil
		},
	}
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return iamFake },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return &fakeEKS{} },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	reader := readerAny.(*awsReader)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSPolicies: []string{policyARN}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if !definitions.Complete {
		t.Fatalf("expected Complete=true, gaps=%+v", definitions.Gaps)
	}
	if len(definitions.Policies) != 1 || definitions.Policies[0].ARN != policyARN {
		t.Fatalf("expected the resolved managed policy, got %+v", definitions.Policies)
	}
	if len(definitions.Policies[0].Grants) != 1 || definitions.Policies[0].Grants[0].ID != "PolicyStatement" {
		t.Fatalf("expected the policy's actual default-version statement, got %+v", definitions.Policies[0].Grants)
	}
}

func TestAWSServiceReferenceRefusesNonAllowlistedPath(t *testing.T) {
	reader := newTestAWSReaderWithHTTP(t, &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath: awsTestMapping,
	}})
	var out any
	_, err := reader.fetchServiceReferenceJSON(context.Background(), "/v1/eks/delete.json", &out)
	if err == nil {
		t.Fatalf("expected a refusal error for a non-allowlisted path")
	}
	_, err = reader.fetchServiceReferenceJSON(context.Background(), "/admin/mutate", &out)
	if err == nil {
		t.Fatalf("expected a refusal error for a path outside /v1")
	}
	_, err = reader.fetchServiceReferenceJSON(context.Background(), "/v1/mapping.json", &out)
	if err == nil {
		t.Fatalf("expected /v1/mapping.json (a different, SDK-keyed document) to be refused: only the root index and /v1/<svc>/<svc>.json are allowlisted")
	}
}

func TestAWSRequestBudgetLimitsServiceReferenceCalls(t *testing.T) {
	transport := &fakeRoundTripper{responses: map[string]string{
		awsTestIndexPath:   awsTestMapping,
		"/v1/eks/eks.json": awsTestEKSDocument,
	}}
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		RequestBudget:    1,
		HTTPClient:       &http.Client{Transport: transport},
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return &fakeIAM{} },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return &fakeEKS{} },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	reader := readerAny.(*awsReader)

	definitions, err := reader.Define(context.Background(), ci.DefinitionRequest{AWSServices: []string{"eks"}})
	if err != nil {
		t.Fatalf("Define: %v", err)
	}
	if definitions.Complete {
		t.Fatalf("expected Complete=false once the request budget is exhausted mid-fetch")
	}
	if len(transport.calls) != 1 {
		t.Fatalf("expected the request budget to stop further calls, got calls=%v", transport.calls)
	}
}
