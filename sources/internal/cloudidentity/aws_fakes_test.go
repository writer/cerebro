package cloudidentitysource

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// fakeSTS is a minimal awsSTSAssumeRoleAPI stub; no network/cloud call ever
// happens through it.
type fakeSTS struct {
	assumeRole func(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	calls      int
}

func (f *fakeSTS) AssumeRole(_ context.Context, params *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.calls++
	if f.assumeRole == nil {
		return nil, fmt.Errorf("fakeSTS: unexpected AssumeRole call")
	}
	return f.assumeRole(params)
}

// fakeIAM is a scriptable awsIAMReadAPI stub covering every read operation
// this reader issues.
type fakeIAM struct {
	getRole                    func(*iam.GetRoleInput) (*iam.GetRoleOutput, error)
	getUser                    func(*iam.GetUserInput) (*iam.GetUserOutput, error)
	listAttachedRolePolicies   func(*iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	listRolePolicies           func(*iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error)
	getRolePolicy              func(*iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error)
	listAttachedUserPolicies   func(*iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error)
	listUserPolicies           func(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error)
	getUserPolicy              func(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error)
	listGroupsForUser          func(*iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error)
	listAttachedGroupPolicies  func(*iam.ListAttachedGroupPoliciesInput) (*iam.ListAttachedGroupPoliciesOutput, error)
	listGroupPolicies          func(*iam.ListGroupPoliciesInput) (*iam.ListGroupPoliciesOutput, error)
	getGroupPolicy             func(*iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error)
	getPolicy                  func(*iam.GetPolicyInput) (*iam.GetPolicyOutput, error)
	getPolicyVersion           func(*iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error)
	listOpenIDConnectProviders func(*iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error)
	getOpenIDConnectProvider   func(*iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error)

	calls map[string]int
}

func (f *fakeIAM) count(name string) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
}

func (f *fakeIAM) GetRole(_ context.Context, params *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	f.count("GetRole")
	if f.getRole == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetRole call")
	}
	return f.getRole(params)
}

func (f *fakeIAM) GetUser(_ context.Context, params *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	f.count("GetUser")
	if f.getUser == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetUser call")
	}
	return f.getUser(params)
}

func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, params *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	f.count("ListAttachedRolePolicies")
	if f.listAttachedRolePolicies == nil {
		return &iam.ListAttachedRolePoliciesOutput{}, nil
	}
	return f.listAttachedRolePolicies(params)
}

func (f *fakeIAM) ListRolePolicies(_ context.Context, params *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	f.count("ListRolePolicies")
	if f.listRolePolicies == nil {
		return &iam.ListRolePoliciesOutput{}, nil
	}
	return f.listRolePolicies(params)
}

func (f *fakeIAM) GetRolePolicy(_ context.Context, params *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	f.count("GetRolePolicy")
	if f.getRolePolicy == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetRolePolicy call")
	}
	return f.getRolePolicy(params)
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, params *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	f.count("ListAttachedUserPolicies")
	if f.listAttachedUserPolicies == nil {
		return &iam.ListAttachedUserPoliciesOutput{}, nil
	}
	return f.listAttachedUserPolicies(params)
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, params *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	f.count("ListUserPolicies")
	if f.listUserPolicies == nil {
		return &iam.ListUserPoliciesOutput{}, nil
	}
	return f.listUserPolicies(params)
}

func (f *fakeIAM) GetUserPolicy(_ context.Context, params *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	f.count("GetUserPolicy")
	if f.getUserPolicy == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetUserPolicy call")
	}
	return f.getUserPolicy(params)
}

func (f *fakeIAM) ListGroupsForUser(_ context.Context, params *iam.ListGroupsForUserInput, _ ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	f.count("ListGroupsForUser")
	if f.listGroupsForUser == nil {
		return &iam.ListGroupsForUserOutput{}, nil
	}
	return f.listGroupsForUser(params)
}

func (f *fakeIAM) ListAttachedGroupPolicies(_ context.Context, params *iam.ListAttachedGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	f.count("ListAttachedGroupPolicies")
	if f.listAttachedGroupPolicies == nil {
		return &iam.ListAttachedGroupPoliciesOutput{}, nil
	}
	return f.listAttachedGroupPolicies(params)
}

func (f *fakeIAM) ListGroupPolicies(_ context.Context, params *iam.ListGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	f.count("ListGroupPolicies")
	if f.listGroupPolicies == nil {
		return &iam.ListGroupPoliciesOutput{}, nil
	}
	return f.listGroupPolicies(params)
}

func (f *fakeIAM) GetGroupPolicy(_ context.Context, params *iam.GetGroupPolicyInput, _ ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	f.count("GetGroupPolicy")
	if f.getGroupPolicy == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetGroupPolicy call")
	}
	return f.getGroupPolicy(params)
}

func (f *fakeIAM) GetPolicy(_ context.Context, params *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	f.count("GetPolicy")
	if f.getPolicy == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetPolicy call")
	}
	return f.getPolicy(params)
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, params *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	f.count("GetPolicyVersion")
	if f.getPolicyVersion == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetPolicyVersion call")
	}
	return f.getPolicyVersion(params)
}

func (f *fakeIAM) ListOpenIDConnectProviders(_ context.Context, params *iam.ListOpenIDConnectProvidersInput, _ ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	f.count("ListOpenIDConnectProviders")
	if f.listOpenIDConnectProviders == nil {
		return &iam.ListOpenIDConnectProvidersOutput{}, nil
	}
	return f.listOpenIDConnectProviders(params)
}

func (f *fakeIAM) GetOpenIDConnectProvider(_ context.Context, params *iam.GetOpenIDConnectProviderInput, _ ...func(*iam.Options)) (*iam.GetOpenIDConnectProviderOutput, error) {
	f.count("GetOpenIDConnectProvider")
	if f.getOpenIDConnectProvider == nil {
		return nil, fmt.Errorf("fakeIAM: unexpected GetOpenIDConnectProvider call")
	}
	return f.getOpenIDConnectProvider(params)
}

// fakeEKS is a scriptable awsEKSReadAPI stub.
type fakeEKS struct {
	describeCluster                func(*eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error)
	listPodIdentityAssociations    func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error)
	describePodIdentityAssociation func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error)
}

func (f *fakeEKS) DescribeCluster(_ context.Context, params *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	if f.describeCluster == nil {
		return nil, fmt.Errorf("fakeEKS: unexpected DescribeCluster call")
	}
	return f.describeCluster(params)
}

func (f *fakeEKS) ListPodIdentityAssociations(_ context.Context, params *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	if f.listPodIdentityAssociations == nil {
		return &eks.ListPodIdentityAssociationsOutput{}, nil
	}
	return f.listPodIdentityAssociations(params)
}

func (f *fakeEKS) DescribePodIdentityAssociation(_ context.Context, params *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if f.describePodIdentityAssociation == nil {
		return nil, fmt.Errorf("fakeEKS: unexpected DescribePodIdentityAssociation call")
	}
	return f.describePodIdentityAssociation(params)
}
