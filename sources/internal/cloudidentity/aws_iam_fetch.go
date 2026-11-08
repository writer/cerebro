package cloudidentitysource

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// resolveManagedPolicy fetches and parses a managed policy's default version,
// caching the result for the lifetime of the reader so repeated attachments
// (and the later Define call) do not refetch the same ARN.
func (r *awsReader) resolveManagedPolicy(ctx context.Context, iamClient awsIAMReadAPI, arn string, now time.Time) (ci.ManagedPolicy, error) {
	if cached, ok := r.policies.get(arn); ok {
		return cached, nil
	}

	if err := r.budget.take(); err != nil {
		return ci.ManagedPolicy{}, err
	}
	policyOut, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return ci.ManagedPolicy{}, fmt.Errorf("get policy %s: %w", arn, err)
	}
	if policyOut.Policy == nil || policyOut.Policy.DefaultVersionId == nil {
		return ci.ManagedPolicy{}, fmt.Errorf("get policy %s: no default version", arn)
	}
	if err := r.budget.take(); err != nil {
		return ci.ManagedPolicy{}, err
	}
	versionOut, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: policyOut.Policy.DefaultVersionId,
	})
	if err != nil {
		return ci.ManagedPolicy{}, fmt.Errorf("get policy version %s/%s: %w", arn, aws.ToString(policyOut.Policy.DefaultVersionId), err)
	}
	if versionOut.PolicyVersion == nil || versionOut.PolicyVersion.Document == nil {
		return ci.ManagedPolicy{}, fmt.Errorf("get policy version %s: no document", arn)
	}
	document, err := awsDecodePolicyDocument(aws.ToString(versionOut.PolicyVersion.Document))
	if err != nil {
		return ci.ManagedPolicy{}, fmt.Errorf("decode policy document %s: %w", arn, err)
	}
	reference := awsReference("iam:GetPolicyVersion", arn, now, ci.DigestString(string(document)))
	grants, err := ci.ParseAWSPolicy(document, reference)
	if err != nil {
		return ci.ManagedPolicy{}, fmt.Errorf("parse policy document %s: %w", arn, err)
	}
	managed := ci.ManagedPolicy{ARN: arn, Grants: grants, References: []ci.Reference{reference}}
	r.policies.store(arn, managed)
	return managed, nil
}

// awsAttachedPolicyPage abstracts the three ListAttached*Policies shapes so
// the pagination loop below is written once.
type awsAttachedPolicyPage struct {
	attached    []types.AttachedPolicy
	isTruncated bool
	marker      *string
}

func (r *awsReader) fetchAttachedPolicies(
	ctx context.Context,
	iamClient awsIAMReadAPI,
	scope string,
	now time.Time,
	page func(ctx context.Context, marker *string) (awsAttachedPolicyPage, error),
) ([]ci.Grant, []ci.ManagedPolicy, bool, []ci.Gap) {
	var refs []ci.Grant
	var policies []ci.ManagedPolicy
	var gaps []ci.Gap
	var marker *string
	for range r.maxPages {
		if err := r.budget.take(); err != nil {
			gaps = append(gaps, awsGap("aws_request_budget_exceeded", scope, "Request budget exhausted before attached policies were fully listed"))
			return refs, policies, false, gaps
		}
		result, err := page(ctx, marker)
		if err != nil {
			gaps = append(gaps, awsGap("aws_attached_policies_unavailable", scope, "Listing attached managed policies did not complete: "+err.Error()))
			return refs, policies, false, gaps
		}
		for _, attached := range result.attached {
			arn := aws.ToString(attached.PolicyArn)
			if arn == "" {
				continue
			}
			refs = append(refs, ci.Grant{Role: arn, References: []ci.Reference{awsReference("iam:ListAttachedPolicies", scope, now, ci.DigestString(arn))}})
			managed, err := r.resolveManagedPolicy(ctx, iamClient, arn, now)
			if err != nil {
				gaps = append(gaps, awsGap("aws_managed_policy_unavailable", arn, "Managed policy default version could not be retrieved: "+err.Error()))
				continue
			}
			policies = append(policies, managed)
		}
		if !result.isTruncated || result.marker == nil {
			return refs, policies, true, gaps
		}
		marker = result.marker
	}
	gaps = append(gaps, awsGap("aws_pagination_limit_reached", scope, "Attached policy pagination exceeded the configured page limit"))
	return refs, policies, false, gaps
}

// awsInlinePolicyPage abstracts the three ListXPolicies (inline name list)
// shapes.
type awsInlinePolicyPage struct {
	names       []string
	isTruncated bool
	marker      *string
}

func (r *awsReader) fetchInlinePolicies(
	ctx context.Context,
	scope string,
	now time.Time,
	list func(ctx context.Context, marker *string) (awsInlinePolicyPage, error),
	get func(ctx context.Context, policyName string) (string, error),
) ([]ci.Grant, bool, []ci.Gap) {
	var grants []ci.Grant
	var gaps []ci.Gap
	var marker *string
	complete := true
	for range r.maxPages {
		if err := r.budget.take(); err != nil {
			gaps = append(gaps, awsGap("aws_request_budget_exceeded", scope, "Request budget exhausted before inline policies were fully listed"))
			return grants, false, gaps
		}
		result, err := list(ctx, marker)
		if err != nil {
			gaps = append(gaps, awsGap("aws_inline_policies_unavailable", scope, "Listing inline policies did not complete: "+err.Error()))
			return grants, false, gaps
		}
		for _, name := range result.names {
			if err := r.budget.take(); err != nil {
				gaps = append(gaps, awsGap("aws_request_budget_exceeded", scope, "Request budget exhausted while fetching inline policy documents"))
				return grants, false, gaps
			}
			raw, err := get(ctx, name)
			if err != nil {
				gaps = append(gaps, awsGap("aws_inline_policy_unavailable", scope+"#"+name, "Inline policy document could not be retrieved: "+err.Error()))
				complete = false
				continue
			}
			document, err := awsDecodePolicyDocument(raw)
			if err != nil {
				gaps = append(gaps, awsGap("aws_inline_policy_undecodable", scope+"#"+name, err.Error()))
				complete = false
				continue
			}
			reference := awsReference("iam:GetPolicy(inline)", scope+"#"+name, now, ci.DigestString(string(document)))
			parsed, err := ci.ParseAWSPolicy(document, reference)
			if err != nil {
				gaps = append(gaps, awsGap("aws_inline_policy_unparseable", scope+"#"+name, err.Error()))
				complete = false
				continue
			}
			grants = append(grants, parsed...)
		}
		if !result.isTruncated || result.marker == nil {
			return grants, complete, gaps
		}
		marker = result.marker
	}
	gaps = append(gaps, awsGap("aws_pagination_limit_reached", scope, "Inline policy pagination exceeded the configured page limit"))
	return grants, false, gaps
}

// fetchBoundary resolves a role/user permission boundary, if any.
func (r *awsReader) fetchBoundary(ctx context.Context, iamClient awsIAMReadAPI, boundary *types.AttachedPermissionsBoundary, scope string, now time.Time) ([]ci.Grant, *ci.ManagedPolicy, []ci.Gap) {
	if boundary == nil || aws.ToString(boundary.PermissionsBoundaryArn) == "" {
		return nil, nil, nil
	}
	arn := aws.ToString(boundary.PermissionsBoundaryArn)
	managed, err := r.resolveManagedPolicy(ctx, iamClient, arn, now)
	if err != nil {
		return nil, nil, []ci.Gap{awsGap("aws_boundary_unavailable", scope, "Permissions boundary policy could not be retrieved: "+err.Error())}
	}
	return managed.Grants, &managed, nil
}

// fetchTrust parses a role's AssumeRolePolicyDocument into trust Grants.
func (r *awsReader) fetchTrust(document *string, scope string, now time.Time) ([]ci.Grant, []ci.Gap) {
	if document == nil || aws.ToString(document) == "" {
		return nil, []ci.Gap{awsGap("aws_trust_policy_missing", scope, "Role has no assume-role trust policy document")}
	}
	decoded, err := awsDecodePolicyDocument(aws.ToString(document))
	if err != nil {
		return nil, []ci.Gap{awsGap("aws_trust_policy_undecodable", scope, err.Error())}
	}
	reference := awsReference("iam:GetRole(trust)", scope, now, ci.DigestString(string(decoded)))
	grants, err := ci.ParseAWSPolicy(decoded, reference)
	if err != nil {
		return nil, []ci.Gap{awsGap("aws_trust_policy_unparseable", scope, err.Error())}
	}
	return grants, nil
}

// fetchGroupsForUser resolves every IAM group a user belongs to and flattens
// each group's attached + inline grants into the user's effective policy
// surface, preserving provenance via Grant.References scope.
func (r *awsReader) fetchGroupsForUser(ctx context.Context, iamClient awsIAMReadAPI, userName, userARN string, now time.Time) ([]ci.Grant, []ci.ManagedPolicy, bool, []ci.Gap) {
	var grants []ci.Grant
	var policies []ci.ManagedPolicy
	var gaps []ci.Gap
	complete := true
	var marker *string
	for range r.maxPages {
		if err := r.budget.take(); err != nil {
			gaps = append(gaps, awsGap("aws_request_budget_exceeded", userARN, "Request budget exhausted before group memberships were fully listed"))
			return grants, policies, false, gaps
		}
		out, err := iamClient.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: aws.String(userName), Marker: marker})
		if err != nil {
			gaps = append(gaps, awsGap("aws_group_membership_unavailable", userARN, "Listing group memberships did not complete: "+err.Error()))
			return grants, policies, false, gaps
		}
		for _, group := range out.Groups {
			groupName := aws.ToString(group.GroupName)
			groupScope := aws.ToString(group.Arn)
			attachedRefs, groupPolicies, attachedComplete, attachedGaps := r.fetchAttachedPolicies(ctx, iamClient, groupScope, now, func(ctx context.Context, marker *string) (awsAttachedPolicyPage, error) {
				out, err := iamClient.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(groupName), Marker: marker})
				if err != nil {
					return awsAttachedPolicyPage{}, err
				}
				return awsAttachedPolicyPage{attached: out.AttachedPolicies, isTruncated: out.IsTruncated, marker: out.Marker}, nil
			})
			// Group attachments apply directly to the user's effective
			// permissions; flatten references (expand via Definitions too).
			grants = append(grants, attachedRefs...)
			policies = append(policies, groupPolicies...)
			complete = complete && attachedComplete
			gaps = append(gaps, attachedGaps...)

			inline, inlineComplete, inlineGaps := r.fetchInlinePolicies(ctx, groupScope, now, func(ctx context.Context, marker *string) (awsInlinePolicyPage, error) {
				out, err := iamClient.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: aws.String(groupName), Marker: marker})
				if err != nil {
					return awsInlinePolicyPage{}, err
				}
				return awsInlinePolicyPage{names: out.PolicyNames, isTruncated: out.IsTruncated, marker: out.Marker}, nil
			}, func(ctx context.Context, policyName string) (string, error) {
				out, err := iamClient.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: aws.String(groupName), PolicyName: aws.String(policyName)})
				if err != nil {
					return "", err
				}
				return aws.ToString(out.PolicyDocument), nil
			})
			grants = append(grants, inline...)
			complete = complete && inlineComplete
			gaps = append(gaps, inlineGaps...)
		}
		if !out.IsTruncated || out.Marker == nil {
			return grants, policies, complete, gaps
		}
		marker = out.Marker
	}
	gaps = append(gaps, awsGap("aws_pagination_limit_reached", userARN, "Group membership pagination exceeded the configured page limit"))
	return grants, policies, false, gaps
}
