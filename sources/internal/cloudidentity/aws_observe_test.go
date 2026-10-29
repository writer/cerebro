package cloudidentitysource

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func fixedAssumeRole(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("AKIDEXAMPLE"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      aws.Time(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)),
	}}, nil
}

func TestAWSObserveRoleComposesTrustBoundaryInlineAndManagedPolicy(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	const boundaryARN = "arn:aws:iam::111111111111:policy/boundary-policy"
	const managedARN = "arn:aws:iam::111111111111:policy/managed-policy"

	trustDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Trust","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub":"system:serviceaccount:default:my-sa"}}}]}`
	inlineDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Inline","Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::my-bucket/*"]}]}`
	boundaryDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Boundary","Effect":"Allow","Action":["s3:*"],"Resource":["*"]}]}`
	managedDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"Managed","Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":["*"]}]}`

	iamFake := &fakeIAM{
		getRole: func(in *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			if aws.ToString(in.RoleName) != "my-role" {
				t.Fatalf("unexpected role name: %s", aws.ToString(in.RoleName))
			}
			return &iam.GetRoleOutput{Role: &iamtypes.Role{
				Arn:                      aws.String(roleARN),
				RoleName:                 aws.String("my-role"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustDoc)),
				PermissionsBoundary:      &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(boundaryARN)},
			}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"inline-policy"}}, nil
		},
		getRolePolicy: func(in *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(url.QueryEscape(inlineDoc))}, nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String(managedARN)}}}, nil
		},
		getPolicy: func(in *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			version := "v1"
			if aws.ToString(in.PolicyArn) == boundaryARN {
				version = "v2"
			}
			return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String(version)}}, nil
		},
		getPolicyVersion: func(in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			doc := managedDoc
			if aws.ToString(in.PolicyArn) == boundaryARN {
				doc = boundaryDoc
			}
			return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(url.QueryEscape(doc))}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=true, gaps=%+v", observation.Policy.Gaps)
	}
	if len(observation.Policy.Grants) != 2 {
		t.Fatalf("expected inline + managed-reference grants, got %+v", observation.Policy.Grants)
	}
	foundInline, foundManagedRef := false, false
	for _, grant := range observation.Policy.Grants {
		if grant.ID == "Inline" {
			foundInline = true
		}
		if grant.Role == managedARN {
			foundManagedRef = true
		}
	}
	if !foundInline || !foundManagedRef {
		t.Fatalf("expected inline grant and unexpanded managed-policy reference, got %+v", observation.Policy.Grants)
	}
	if len(observation.Policy.Boundaries) != 1 || len(observation.Policy.Boundaries[0]) != 1 || observation.Policy.Boundaries[0][0].ID != "Boundary" {
		t.Fatalf("expected one boundary with its expanded grant, got %+v", observation.Policy.Boundaries)
	}
	if len(observation.Policy.Trust) != 1 || observation.Policy.Trust[0].ID != "Trust" {
		t.Fatalf("expected expanded trust grant, got %+v", observation.Policy.Trust)
	}
	if len(observation.Policy.Trust[0].Members) == 0 {
		t.Fatalf("expected trust grant to carry Federated principal members")
	}
	if !observation.Definitions.Complete {
		t.Fatalf("expected Definitions.Complete=true")
	}
	var sawManaged, sawBoundary bool
	for _, policy := range observation.Definitions.Policies {
		if policy.ARN == managedARN && len(policy.Grants) == 1 && policy.Grants[0].ID == "Managed" {
			sawManaged = true
		}
		if policy.ARN == boundaryARN && len(policy.Grants) == 1 && policy.Grants[0].ID == "Boundary" {
			sawBoundary = true
		}
	}
	if !sawManaged || !sawBoundary {
		t.Fatalf("expected both attached managed policy and boundary policy expanded in Definitions.Policies, got %+v", observation.Definitions.Policies)
	}
}

// TestAWSObserveRoleMissingTrustDocumentIsIncomplete reproduces the
// exercised counterexample: a role with no AssumeRolePolicyDocument must
// never be read as a complete, trust-free policy.
func TestAWSObserveRoleMissingTrustDocumentIsIncomplete(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false for a role with no trust document, got true (gaps=%+v)", observation.Policy.Gaps)
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "aws_trust_policy_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected aws_trust_policy_missing gap, got %+v", observation.Policy.Gaps)
	}
}

// TestAWSObserveRoleUndecodableTrustDocumentIsIncomplete reproduces the
// exercised counterexample: an AssumeRolePolicyDocument with invalid
// percent-encoding must never be read as a complete, trust-free policy.
func TestAWSObserveRoleUndecodableTrustDocumentIsIncomplete(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{
				Arn:                      aws.String(roleARN),
				RoleName:                 aws.String("my-role"),
				AssumeRolePolicyDocument: aws.String("%ZZ-not-valid-percent-encoding"),
			}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false for an undecodable trust document, got true (gaps=%+v)", observation.Policy.Gaps)
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "aws_trust_policy_undecodable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected aws_trust_policy_undecodable gap, got %+v", observation.Policy.Gaps)
	}
}

// TestAWSObserveRoleUnparseableTrustDocumentIsIncomplete reproduces the
// exercised counterexample: a trust document that decodes to invalid JSON
// must never be read as a complete, trust-free policy.
func TestAWSObserveRoleUnparseableTrustDocumentIsIncomplete(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{
				Arn:                      aws.String(roleARN),
				RoleName:                 aws.String("my-role"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[`),
			}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false for an unparseable trust document, got true (gaps=%+v)", observation.Policy.Gaps)
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "aws_trust_policy_unparseable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected aws_trust_policy_unparseable gap, got %+v", observation.Policy.Gaps)
	}
}

func TestAWSObserveRoleObservationCachedAcrossCalls(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})
	request := ci.CloudRequest{Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"}}
	if _, err := reader.Observe(context.Background(), request); err != nil {
		t.Fatalf("first Observe: %v", err)
	}
	if _, err := reader.Observe(context.Background(), request); err != nil {
		t.Fatalf("second Observe: %v", err)
	}
	if iamFake.calls["GetRole"] != 1 {
		t.Fatalf("expected role observation to be cached within the run, got %d GetRole calls", iamFake.calls["GetRole"])
	}
}

func TestAWSObserveMidPaginationErrorKeepsPartialResultsIncomplete(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	const firstARN = "arn:aws:iam::111111111111:policy/first-policy"
	firstDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"First","Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`

	calls := 0
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
		listAttachedRolePolicies: func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			calls++
			if calls == 1 {
				return &iam.ListAttachedRolePoliciesOutput{
					AttachedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: aws.String(firstARN)}},
					IsTruncated:      true,
					Marker:           aws.String("page-2"),
				}, nil
			}
			return nil, fmt.Errorf("throttled")
		},
		getPolicy: func(*iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")}}, nil
		},
		getPolicyVersion: func(*iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(firstDoc)}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false after a mid-pagination error")
	}
	found := false
	for _, grant := range observation.Policy.Grants {
		if grant.Role == firstARN {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the first page's managed-policy reference to survive a later page's error, got %+v", observation.Policy.Grants)
	}
	hasGap := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "aws_attached_policies_unavailable" {
			hasGap = true
		}
	}
	if !hasGap {
		t.Fatalf("expected a scoped pagination gap, got %+v", observation.Policy.Gaps)
	}
}

func TestAWSObserveUserComposesGroupPolicies(t *testing.T) {
	const userARN = "arn:aws:iam::111111111111:user/my-user"
	groupInlineDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"GroupInline","Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":["*"]}]}`

	iamFake := &fakeIAM{
		getUser: func(*iam.GetUserInput) (*iam.GetUserOutput, error) {
			return &iam.GetUserOutput{User: &iamtypes.User{Arn: aws.String(userARN), UserName: aws.String("my-user")}}, nil
		},
		listGroupsForUser: func(*iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error) {
			return &iam.ListGroupsForUserOutput{Groups: []iamtypes.Group{{GroupName: aws.String("my-group"), Arn: aws.String("arn:aws:iam::111111111111:group/my-group")}}}, nil
		},
		listGroupPolicies: func(*iam.ListGroupPoliciesInput) (*iam.ListGroupPoliciesOutput, error) {
			return &iam.ListGroupPoliciesOutput{PolicyNames: []string{"group-inline"}}, nil
		},
		getGroupPolicy: func(*iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error) {
			return &iam.GetGroupPolicyOutput{PolicyDocument: aws.String(groupInlineDoc)}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: userARN, Provider: ci.AWS, Kind: "aws_iam_user", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("expected Policy.Complete=true, gaps=%+v", observation.Policy.Gaps)
	}
	if observation.Policy.Trust != nil {
		t.Fatalf("expected no trust grants for an IAM user, got %+v", observation.Policy.Trust)
	}
	if len(observation.Policy.Grants) != 1 || observation.Policy.Grants[0].ID != "GroupInline" {
		t.Fatalf("expected the group's inline grant flattened into the user's effective grants, got %+v", observation.Policy.Grants)
	}
	if iamFake.calls["GetUser"] != 1 {
		t.Fatalf("expected exactly one GetUser call, got %d", iamFake.calls["GetUser"])
	}
}

func TestAWSObserveComputedIssuerResolution(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	const issuer = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	const providerARN = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"

	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
		listOpenIDConnectProviders: func(*iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error) {
			return &iam.ListOpenIDConnectProvidersOutput{OpenIDConnectProviderList: []iamtypes.OpenIDConnectProviderListEntry{{Arn: aws.String(providerARN)}}}, nil
		},
	}
	eksFake := &fakeEKS{describeCluster: func(in *eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
		if aws.ToString(in.Name) != "my-cluster" {
			t.Fatalf("unexpected cluster name: %s", aws.ToString(in.Name))
		}
		return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: aws.String(issuer)}}}}, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
		Consumers: []ci.Workload{{ID: "w1", Cluster: "my-cluster", Region: "us-east-1"}},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_issuer:my-cluster"] != issuer {
		t.Fatalf("expected resolved issuer, got %+v", observation.ResolvedIdentifiers)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_provider_arn:my-cluster"] != providerARN {
		t.Fatalf("expected resolved provider arn, got %+v", observation.ResolvedIdentifiers)
	}
}

func TestAWSObservePodIdentityResolvesRole(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/resolved-role"
	const principalID = "k8s://my-cluster/my-ns/sa/my-sa"

	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("resolved-role")}}, nil
		},
	}
	eksFake := &fakeEKS{
		listPodIdentityAssociations: func(in *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			if aws.ToString(in.ClusterName) != "my-cluster" || aws.ToString(in.Namespace) != "my-ns" || aws.ToString(in.ServiceAccount) != "my-sa" {
				t.Fatalf("unexpected list filters: %+v", in)
			}
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{{AssociationId: aws.String("assoc-1")}}}, nil
		},
		describePodIdentityAssociation: func(in *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
			return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{RoleArn: aws.String(roleARN)}}, nil
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: principalID, Provider: ci.AWS, Kind: "aws_kubernetes_service_account", Account: "111111111111"},
		Consumers: []ci.Workload{{ID: "w1", Cluster: "my-cluster", Region: "us-east-1"}},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.ResolvedIdentifiers["aws_pod_identity_role:"+principalID] != roleARN {
		t.Fatalf("expected resolved pod identity role alias, got %+v", observation.ResolvedIdentifiers)
	}
}

func TestAWSObservePodIdentityNoAssociationIsCompleteNotFailure(t *testing.T) {
	iamFake := &fakeIAM{}
	eksFake := &fakeEKS{listPodIdentityAssociations: func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		return &eks.ListPodIdentityAssociationsOutput{}, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "k8s://my-cluster/my-ns/sa/my-sa", Provider: ci.AWS, Kind: "aws_kubernetes_service_account", Account: "111111111111"},
		Consumers: []ci.Workload{{ID: "w1", Cluster: "my-cluster", Region: "us-east-1"}},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !observation.Policy.Complete {
		t.Fatalf("expected a confirmed absence to be Complete=true, not an access failure")
	}
	if len(observation.Policy.Grants) != 0 {
		t.Fatalf("expected no grants, got %+v", observation.Policy.Grants)
	}
	if iamFake.calls["GetRole"] != 0 {
		t.Fatalf("expected no role fetch when no pod identity association exists")
	}
}

func TestAWSObservePodIdentityMissingAccountIsIncomplete(t *testing.T) {
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, &fakeIAM{}, &fakeEKS{})
	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "k8s://my-cluster/my-ns/sa/my-sa", Provider: ci.AWS, Kind: "aws_kubernetes_service_account"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Complete=false when account is unresolved")
	}
	if len(observation.Gaps) == 0 {
		t.Fatalf("expected a scoped gap for the unresolved account")
	}
}

func TestAWSObserveUnsupportedPrincipalKind(t *testing.T) {
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, &fakeIAM{}, &fakeEKS{})
	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "something", Provider: ci.AWS, Kind: "unknown"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatalf("expected Complete=false for an unsupported principal kind")
	}
	if len(observation.Policy.Grants) != 0 {
		t.Fatalf("expected no fabricated grants, got %+v", observation.Policy.Grants)
	}
}

func TestAWSObserveWorkloadLinkageUsesPerClusterRegion(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
	}
	var mu sync.Mutex
	seenRegions := map[string]bool{}
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:           aws.Config{Region: "us-east-1"},
		RoleName:         "cerebro-org-scan-role",
		Clock:            func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return iamFake },
		EKSClientFactory: func(cfg aws.Config) awsEKSReadAPI {
			mu.Lock()
			seenRegions[cfg.Region] = true
			mu.Unlock()
			region := cfg.Region
			return &fakeEKS{describeCluster: func(*eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
				return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: aws.String("https://oidc.eks." + region + ".amazonaws.com/id/EXAMPLE")}}}}, nil
			}}
		},
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	reader := readerAny.(*awsReader)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
		Consumers: []ci.Workload{
			{ID: "w1", Cluster: "cluster-a", Region: "us-east-1"},
			{ID: "w2", Cluster: "cluster-b", Region: "eu-west-1"},
		},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !seenRegions["us-east-1"] || !seenRegions["eu-west-1"] {
		t.Fatalf("EKSClientFactory saw regions %+v, want both us-east-1 and eu-west-1", seenRegions)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_issuer:cluster-a"] == "" {
		t.Fatalf("expected cluster-a's issuer resolved against its own us-east-1 region, got %+v", observation.ResolvedIdentifiers)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_issuer:cluster-b"] == "" {
		t.Fatalf("expected cluster-b's issuer resolved against its own eu-west-1 region, got %+v", observation.ResolvedIdentifiers)
	}
}

func TestAWSObserveWorkloadLinkageEmptyRegionIsScopedGap(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
	}
	eksFake := &fakeEKS{describeCluster: func(*eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
		t.Fatal("DescribeCluster must not be called when the cluster's region is unresolved")
		return nil, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
		Consumers: []ci.Workload{{ID: "w1", Cluster: "my-cluster"}}, // no Region: must not fall back to the reader-wide default
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	found := false
	for _, gap := range observation.Gaps {
		if gap.Code == "aws_eks_cluster_region_unresolved" && gap.Scope == "my-cluster" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want aws_eks_cluster_region_unresolved scoped to my-cluster", observation.Gaps)
	}
}

func TestAWSObservePodIdentityEmptyRegionIsScopedGap(t *testing.T) {
	eksFake := &fakeEKS{listPodIdentityAssociations: func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		t.Fatal("ListPodIdentityAssociations must not be called when the cluster's region is unresolved")
		return nil, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, &fakeIAM{}, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		// No Consumers at all: the KSA's cluster region cannot be resolved.
		Principal: ci.Principal{ID: "k8s://my-cluster/my-ns/sa/my-sa", Provider: ci.AWS, Kind: "aws_kubernetes_service_account", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("expected Complete=false when the Pod Identity subject's cluster region is unresolved")
	}
	found := false
	for _, gap := range observation.Gaps {
		if gap.Code == "aws_eks_cluster_region_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want aws_eks_cluster_region_unresolved", observation.Gaps)
	}
}

// TestAWSObserveWorkloadLinkageAmbiguousClusterNameResolvesNeither
// reproduces the exercised counterexample: two consumers report the same
// cluster name ("prod") but disagree on region (and/or account). Resolving
// only the first-seen one and keying the result by cluster name alone would
// silently attribute one cluster's OIDC issuer/provider to both. Neither
// side may be resolved; only a scoped ambiguity gap may be reported.
func TestAWSObserveWorkloadLinkageAmbiguousClusterNameResolvesNeither(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
	}
	eksFake := &fakeEKS{describeCluster: func(*eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
		t.Fatal("DescribeCluster must not be called for an ambiguous cluster name")
		return nil, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
		Consumers: []ci.Workload{
			{ID: "east", Cluster: "prod", Region: "us-east-1", CloudAccount: "111111111111"},
			{ID: "west", Cluster: "prod", Region: "us-west-2", CloudAccount: "222222222222"},
		},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_issuer:prod"] != "" {
		t.Fatalf("expected no issuer resolved for an ambiguous cluster name, got %+v", observation.ResolvedIdentifiers)
	}
	if observation.ResolvedIdentifiers["aws_eks_oidc_provider_arn:prod"] != "" {
		t.Fatalf("expected no provider ARN resolved for an ambiguous cluster name, got %+v", observation.ResolvedIdentifiers)
	}
	found := false
	for _, gap := range observation.Gaps {
		if gap.Code == "aws_eks_cluster_name_ambiguous" && gap.Scope == "prod" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want aws_eks_cluster_name_ambiguous scoped to prod", observation.Gaps)
	}
}

// TestAWSObservePodIdentityAmbiguousClusterNameIsIncomplete covers the same
// ambiguity on the Pod Identity (aws_kubernetes_service_account) path: the
// subject's cluster name must not be resolved to either consumer's region
// when consumers disagree on this cluster name's location.
func TestAWSObservePodIdentityAmbiguousClusterNameIsIncomplete(t *testing.T) {
	eksFake := &fakeEKS{listPodIdentityAssociations: func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		t.Fatal("ListPodIdentityAssociations must not be called for an ambiguous cluster name")
		return nil, nil
	}}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, &fakeIAM{}, eksFake)

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: "k8s://prod/my-ns/sa/my-sa", Provider: ci.AWS, Kind: "aws_kubernetes_service_account", Account: "111111111111"},
		Consumers: []ci.Workload{
			{ID: "east", Cluster: "prod", Region: "us-east-1", CloudAccount: "111111111111"},
			{ID: "west", Cluster: "prod", Region: "us-west-2", CloudAccount: "222222222222"},
		},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("expected Complete=false when the Pod Identity subject's cluster name is ambiguous")
	}
	found := false
	for _, gap := range observation.Gaps {
		if gap.Code == "aws_eks_cluster_name_ambiguous" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want aws_eks_cluster_name_ambiguous", observation.Gaps)
	}
}

func TestAWSObserveInlinePolicyFetchFailureIsIncomplete(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"broken-policy"}}, nil
		},
		getRolePolicy: func(*iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			return nil, fmt.Errorf("AccessDenied: user is not authorized to perform iam:GetRolePolicy")
		},
	}
	reader := newTestAWSReader(t, &fakeSTS{assumeRole: fixedAssumeRole}, iamFake, &fakeEKS{})

	observation, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if observation.Policy.Complete {
		t.Fatal("Policy.Complete = true despite a denied GetRolePolicy call; the omitted grants were silently treated as a complete live surface")
	}
	found := false
	for _, gap := range observation.Policy.Gaps {
		if gap.Code == "aws_inline_policy_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Gaps = %+v, want aws_inline_policy_unavailable", observation.Policy.Gaps)
	}
}

func TestAWSObserveInlinePolicyListNotDoubleChargedAgainstBudget(t *testing.T) {
	const roleARN = "arn:aws:iam::111111111111:role/my-role"
	iamFake := &fakeIAM{
		getRole: func(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String(roleARN), RoleName: aws.String("my-role")}}, nil
		},
		listRolePolicies: func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{}, nil
		},
	}
	readerAny, err := NewAWSReader(context.Background(), AWSOptions{
		Config:   aws.Config{Region: "us-east-1"},
		RoleName: "cerebro-org-scan-role",
		// Sized for exactly AssumeRole + GetRole + one ListRolePolicies
		// call: a duplicate charge on the list call would refuse it before
		// the real API call ever happens.
		RequestBudget:    3,
		Clock:            func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		STSClientFactory: func(aws.Config) awsSTSAssumeRoleAPI { return &fakeSTS{assumeRole: fixedAssumeRole} },
		IAMClientFactory: func(aws.Config) awsIAMReadAPI { return iamFake },
		EKSClientFactory: func(aws.Config) awsEKSReadAPI { return &fakeEKS{} },
	})
	if err != nil {
		t.Fatalf("NewAWSReader: %v", err)
	}
	reader := readerAny.(*awsReader)

	if _, err := reader.Observe(context.Background(), ci.CloudRequest{
		Principal: ci.Principal{ID: roleARN, Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"},
	}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if iamFake.calls["ListRolePolicies"] != 1 {
		t.Fatalf("ListRolePolicies calls = %d, want exactly 1: a budget sized for AssumeRole+GetRole+one ListRolePolicies call must not refuse the list to a duplicate charge", iamFake.calls["ListRolePolicies"])
	}
}
