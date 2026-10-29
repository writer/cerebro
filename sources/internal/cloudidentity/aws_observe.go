package cloudidentitysource

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// Observe implements ci.CloudReader. It never fabricates an empty-permission
// result on access failure: a failed live fetch always sets Complete=false
// and attaches a scoped Gap, leaving any partially-collected grants intact.
func (r *awsReader) Observe(ctx context.Context, request ci.CloudRequest) (ci.Observation, error) {
	now := r.clock().UTC()
	principal := request.Principal

	switch principal.Kind {
	case "aws_iam_role", "aws_iam_user":
		parsed, ok := awsParseIAMPrincipalARN(principal.ID)
		if !ok {
			return r.incompleteObservation(principal.ID, "aws_principal_arn_unparseable", "Principal ID is not a recognizable IAM role/user ARN"), nil
		}
		policy, definitions, gaps := r.observeRole(ctx, parsed.ARN, now)
		var resolved map[string]string
		if principal.Kind == "aws_iam_role" {
			// IRSA/OIDC trust confirmation only applies to roles; IAM users
			// have no assume-role trust policy or federated identity.
			var linkGaps []ci.Gap
			resolved, linkGaps = r.resolveWorkloadLinkage(ctx, parsed, request.Consumers)
			gaps = append(gaps, linkGaps...)
		}
		return ci.Observation{Policy: policy, Definitions: definitions, ResolvedIdentifiers: resolved, Gaps: gaps}, nil

	case "aws_kubernetes_service_account":
		subject, ok := awsParsePodIdentitySubject(principal.ID)
		if !ok {
			return r.incompleteObservation(principal.ID, "aws_principal_id_unparseable", "Principal ID is not a recognizable k8s://cluster/namespace/sa/name subject"), nil
		}
		if principal.Account == "" {
			return r.incompleteObservation(principal.ID, "aws_pod_identity_account_unresolved", "No account was provided to resolve EKS Pod Identity associations for this service account"), nil
		}
		// EKS reads are regional; the reader-wide default region must never
		// silently stand in for the consumer's actual cluster location
		// (see resolveWorkloadLinkage below for the IRSA-role equivalent).
		region, ambiguous := awsConsumerRegionForCluster(request.Consumers, subject.Cluster)
		if ambiguous {
			return r.incompleteObservation(principal.ID, "aws_eks_cluster_name_ambiguous", "Multiple consumers report this Kubernetes service account's cluster name with different accounts/regions; refusing to guess which one to query"), nil
		}
		if region == "" {
			return r.incompleteObservation(principal.ID, "aws_eks_cluster_region_unresolved", "No region is known for this Kubernetes service account's cluster; refusing to query a default/fallback region"), nil
		}
		roleARN, found, gaps, err := r.resolvePodIdentityRole(ctx, principal.Account, region, subject)
		if err != nil {
			gaps = append(gaps, awsGap("aws_pod_identity_lookup_failed", principal.ID, "EKS Pod Identity association lookup did not complete: "+err.Error()))
			return ci.Observation{Policy: ci.PolicyState{Complete: false, ObservedAt: now, Gaps: gaps}, Definitions: ci.Definitions{Complete: false}, Gaps: gaps}, nil //nolint:nilerr // Observe's documented contract degrades access failures to a scoped Gap, never a returned error.
		}
		if !found {
			// A successful, exhaustive lookup that found no association is a
			// genuine determination, not an access failure: no grants is the
			// correct (and complete) observation here.
			return ci.Observation{Policy: ci.PolicyState{Complete: true, ObservedAt: now, Gaps: gaps}, Definitions: ci.Definitions{Complete: true}, Gaps: gaps}, nil
		}
		policy, definitions, roleGaps := r.observeRole(ctx, roleARN, now)
		gaps = append(gaps, roleGaps...)
		resolved := map[string]string{"aws_pod_identity_role:" + principal.ID: roleARN}
		return ci.Observation{Policy: policy, Definitions: definitions, ResolvedIdentifiers: resolved, Gaps: gaps}, nil

	default:
		return r.incompleteObservation(principal.ID, "aws_principal_kind_unsupported", fmt.Sprintf("Unsupported AWS principal kind %q", principal.Kind)), nil
	}
}

func (r *awsReader) incompleteObservation(scope, code, message string) ci.Observation {
	gap := awsGap(code, scope, message)
	return ci.Observation{
		Policy:      ci.PolicyState{Complete: false, ObservedAt: r.clock().UTC(), Gaps: []ci.Gap{gap}},
		Definitions: ci.Definitions{Complete: false},
		Gaps:        []ci.Gap{gap},
	}
}

// observeRole fetches (or reuses this run's cached) live policy state for one
// IAM role ARN: trust, permissions boundary, inline policies, and attached
// managed-policy references plus their expanded definitions.
func (r *awsReader) observeRoleByARNCached(roleARN string) (awsRoleObservation, bool) {
	r.roleMu.Lock()
	defer r.roleMu.Unlock()
	cached, ok := r.roleCache[roleARN]
	return cached, ok
}

func (r *awsReader) storeRoleObservation(roleARN string, observation awsRoleObservation) {
	r.roleMu.Lock()
	defer r.roleMu.Unlock()
	r.roleCache[roleARN] = observation
}

func (r *awsReader) observeRole(ctx context.Context, roleARN string, now time.Time) (ci.PolicyState, ci.Definitions, []ci.Gap) {
	if cached, ok := r.observeRoleByARNCached(roleARN); ok {
		if cached.err != nil {
			gap := awsGap("aws_role_observation_failed", roleARN, cached.err.Error())
			return ci.PolicyState{Complete: false, ObservedAt: now, Gaps: []ci.Gap{gap}}, ci.Definitions{Complete: false}, []ci.Gap{gap}
		}
		return cached.policy, cached.definitions, cached.policy.Gaps
	}

	parsed, ok := awsParseIAMPrincipalARN(roleARN)
	if !ok {
		err := fmt.Errorf("not a recognizable IAM role/user ARN: %s", roleARN)
		r.storeRoleObservation(roleARN, awsRoleObservation{err: err})
		gap := awsGap("aws_role_arn_invalid", roleARN, err.Error())
		return ci.PolicyState{Complete: false, ObservedAt: now, Gaps: []ci.Gap{gap}}, ci.Definitions{Complete: false}, []ci.Gap{gap}
	}

	var policy ci.PolicyState
	var definitions ci.Definitions
	var err error
	if parsed.Kind == "user" {
		policy, definitions, err = r.fetchUser(ctx, parsed, now)
	} else {
		policy, definitions, err = r.fetchRole(ctx, parsed, now)
	}
	r.storeRoleObservation(roleARN, awsRoleObservation{policy: policy, definitions: definitions, err: err})
	if err != nil {
		gap := awsGap("aws_role_observation_failed", roleARN, err.Error())
		policy.Complete = false
		policy.Gaps = append(policy.Gaps, gap)
		definitions.Complete = false
		return policy, definitions, append([]ci.Gap{}, policy.Gaps...)
	}
	return policy, definitions, policy.Gaps
}

// fetchRole issues every live IAM call needed to observe one role: trust,
// boundary, inline policies, and attached managed-policy references.
func (r *awsReader) fetchRole(ctx context.Context, principal awsIAMPrincipal, now time.Time) (ci.PolicyState, ci.Definitions, error) {
	cfg, err := r.assumedConfig(ctx, principal.Account)
	if err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("assume role into account %s: %w", principal.Account, err)
	}
	iamClient := r.options.IAMClientFactory(cfg)

	if err := r.budget.take(); err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, err
	}
	roleOut, err := iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(principal.Name)})
	if err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("get role %s: %w", principal.ARN, err)
	}
	if roleOut.Role == nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("get role %s: empty response", principal.ARN)
	}
	role := roleOut.Role
	scope := principal.ARN

	var gaps []ci.Gap
	complete := true

	trustGrants, trustGaps := r.fetchTrust(role.AssumeRolePolicyDocument, scope, now)
	gaps = append(gaps, trustGaps...)
	complete = complete && len(trustGaps) == 0

	boundaryGrants, boundaryPolicy, boundaryGaps := r.fetchBoundary(ctx, iamClient, role.PermissionsBoundary, scope, now)
	gaps = append(gaps, boundaryGaps...)
	complete = complete && len(boundaryGaps) == 0

	inlineGrants, inlineComplete, inlineGaps := r.fetchInlinePolicies(ctx, scope, now,
		func(ctx context.Context, marker *string) (awsInlinePolicyPage, error) {
			out, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(principal.Name), Marker: marker})
			if err != nil {
				return awsInlinePolicyPage{}, err
			}
			return awsInlinePolicyPage{names: out.PolicyNames, isTruncated: out.IsTruncated, marker: out.Marker}, nil
		},
		func(ctx context.Context, policyName string) (string, error) {
			out, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(principal.Name), PolicyName: aws.String(policyName)})
			if err != nil {
				return "", err
			}
			return aws.ToString(out.PolicyDocument), nil
		})
	gaps = append(gaps, inlineGaps...)
	complete = complete && inlineComplete

	attachedRefs, attachedPolicies, attachedComplete, attachedGaps := r.fetchAttachedPolicies(ctx, iamClient, scope, now,
		func(ctx context.Context, marker *string) (awsAttachedPolicyPage, error) {
			out, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(principal.Name), Marker: marker})
			if err != nil {
				return awsAttachedPolicyPage{}, err
			}
			return awsAttachedPolicyPage{attached: out.AttachedPolicies, isTruncated: out.IsTruncated, marker: out.Marker}, nil
		})
	gaps = append(gaps, attachedGaps...)
	complete = complete && attachedComplete

	grants := append(append([]ci.Grant{}, inlineGrants...), attachedRefs...)
	var boundaries [][]ci.Grant
	if len(boundaryGrants) > 0 {
		boundaries = append(boundaries, boundaryGrants)
	}
	policy := ci.PolicyState{
		Grants:     grants,
		Boundaries: boundaries,
		Trust:      trustGrants,
		Complete:   complete,
		ObservedAt: now,
		References: []ci.Reference{awsReference("iam:GetRole", scope, now, ci.Digest(scope))},
		Gaps:       gaps,
	}
	definitions := ci.Definitions{Policies: attachedPolicies, Complete: true}
	if boundaryPolicy != nil {
		definitions.Policies = append(definitions.Policies, *boundaryPolicy)
	}
	// Digest left unset; the collection pipeline recomputes it canonically
	// after merging (per IamAssessment).
	return policy, definitions, nil
}

// fetchUser issues every live IAM call needed to observe one IAM user:
// boundary, inline policies, attached managed-policy references, and every
// group membership's attached/inline policies flattened into the user's
// effective grants. IAM users have no trust policy; Trust stays nil, which
// is a correct absence, not a gap.
func (r *awsReader) fetchUser(ctx context.Context, principal awsIAMPrincipal, now time.Time) (ci.PolicyState, ci.Definitions, error) {
	cfg, err := r.assumedConfig(ctx, principal.Account)
	if err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("assume role into account %s: %w", principal.Account, err)
	}
	iamClient := r.options.IAMClientFactory(cfg)

	if err := r.budget.take(); err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, err
	}
	userOut, err := iamClient.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(principal.Name)})
	if err != nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("get user %s: %w", principal.ARN, err)
	}
	if userOut.User == nil {
		return ci.PolicyState{Complete: false, ObservedAt: now}, ci.Definitions{Complete: false}, fmt.Errorf("get user %s: empty response", principal.ARN)
	}
	user := userOut.User
	scope := principal.ARN

	var gaps []ci.Gap
	complete := true

	boundaryGrants, boundaryPolicy, boundaryGaps := r.fetchBoundary(ctx, iamClient, user.PermissionsBoundary, scope, now)
	gaps = append(gaps, boundaryGaps...)
	complete = complete && len(boundaryGaps) == 0

	inlineGrants, inlineComplete, inlineGaps := r.fetchInlinePolicies(ctx, scope, now,
		func(ctx context.Context, marker *string) (awsInlinePolicyPage, error) {
			out, err := iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(principal.Name), Marker: marker})
			if err != nil {
				return awsInlinePolicyPage{}, err
			}
			return awsInlinePolicyPage{names: out.PolicyNames, isTruncated: out.IsTruncated, marker: out.Marker}, nil
		},
		func(ctx context.Context, policyName string) (string, error) {
			out, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(principal.Name), PolicyName: aws.String(policyName)})
			if err != nil {
				return "", err
			}
			return aws.ToString(out.PolicyDocument), nil
		})
	gaps = append(gaps, inlineGaps...)
	complete = complete && inlineComplete

	attachedRefs, attachedPolicies, attachedComplete, attachedGaps := r.fetchAttachedPolicies(ctx, iamClient, scope, now,
		func(ctx context.Context, marker *string) (awsAttachedPolicyPage, error) {
			out, err := iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(principal.Name), Marker: marker})
			if err != nil {
				return awsAttachedPolicyPage{}, err
			}
			return awsAttachedPolicyPage{attached: out.AttachedPolicies, isTruncated: out.IsTruncated, marker: out.Marker}, nil
		})
	gaps = append(gaps, attachedGaps...)
	complete = complete && attachedComplete

	groupGrants, groupPolicies, groupComplete, groupGaps := r.fetchGroupsForUser(ctx, iamClient, principal.Name, scope, now)
	gaps = append(gaps, groupGaps...)
	complete = complete && groupComplete

	grants := append(append(append([]ci.Grant{}, inlineGrants...), attachedRefs...), groupGrants...)
	var boundaries [][]ci.Grant
	if len(boundaryGrants) > 0 {
		boundaries = append(boundaries, boundaryGrants)
	}
	policy := ci.PolicyState{
		Grants:     grants,
		Boundaries: boundaries,
		Complete:   complete,
		ObservedAt: now,
		References: []ci.Reference{awsReference("iam:GetUser", scope, now, ci.Digest(scope))},
		Gaps:       gaps,
	}
	definitions := ci.Definitions{Policies: append(attachedPolicies, groupPolicies...), Complete: true}
	if boundaryPolicy != nil {
		definitions.Policies = append(definitions.Policies, *boundaryPolicy)
	}
	// Digest left unset; the collection pipeline recomputes it canonically
	// after merging (per IamAssessment).
	return policy, definitions, nil
}

// resolvePodIdentityRole resolves the live EKS Pod Identity association (if
// any) binding subject's cluster/namespace/service-account to an IAM role.
// region is the consumer-reported location of subject.Cluster: EKS reads
// are regional, so the EKS client is built for that exact region rather
// than the reader-wide default.
func (r *awsReader) resolvePodIdentityRole(ctx context.Context, account string, region string, subject awsPodIdentitySubject) (string, bool, []ci.Gap, error) {
	cfg, err := r.assumedConfigForRegion(ctx, account, region)
	if err != nil {
		return "", false, nil, fmt.Errorf("assume role into account %s: %w", account, err)
	}
	eksClient := r.options.EKSClientFactory(cfg)
	if err := r.budget.take(); err != nil {
		return "", false, nil, err
	}
	listOut, err := eksClient.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
		ClusterName:    aws.String(subject.Cluster),
		Namespace:      aws.String(subject.Namespace),
		ServiceAccount: aws.String(subject.ServiceAccount),
	})
	if err != nil {
		return "", false, nil, fmt.Errorf("list pod identity associations: %w", err)
	}
	if len(listOut.Associations) == 0 {
		return "", false, nil, nil
	}
	associationID := aws.ToString(listOut.Associations[0].AssociationId)
	if err := r.budget.take(); err != nil {
		return "", false, nil, err
	}
	describeOut, err := eksClient.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		ClusterName:   aws.String(subject.Cluster),
		AssociationId: aws.String(associationID),
	})
	if err != nil {
		return "", false, nil, fmt.Errorf("describe pod identity association %s: %w", associationID, err)
	}
	if describeOut.Association == nil || aws.ToString(describeOut.Association.RoleArn) == "" {
		return "", false, nil, fmt.Errorf("describe pod identity association %s: empty role arn", associationID)
	}
	var gaps []ci.Gap
	if len(listOut.Associations) > 1 {
		gaps = append(gaps, awsGap("aws_pod_identity_multiple_associations", subject.Cluster+"/"+subject.Namespace+"/"+subject.ServiceAccount, "More than one EKS Pod Identity association matched; only the first was resolved"))
	}
	return aws.ToString(describeOut.Association.RoleArn), true, gaps, nil
}

// resolveWorkloadLinkage cross-checks an IRSA role's live trust policy
// against the EKS cluster OIDC issuer/provider for every distinct cluster
// among request consumers, so drift between the configured annotation link
// and the role's actual trust statements is observable. Each cluster's EKS
// client is built for that cluster's own reported region (Workload.Region);
// a cluster with no known region is an explicit scoped gap, never silently
// queried against the reader-wide default region.
func (r *awsReader) resolveWorkloadLinkage(ctx context.Context, principal awsIAMPrincipal, consumers []ci.Workload) (map[string]string, []ci.Gap) {
	locations, ambiguousClusters := awsConsumerClusterLocations(consumers)
	if len(locations) == 0 && len(ambiguousClusters) == 0 {
		return nil, nil
	}
	iamCfg, err := r.assumedConfig(ctx, principal.Account)
	if err != nil {
		return nil, []ci.Gap{awsGap("aws_eks_issuer_unavailable", principal.ARN, "Could not assume role to resolve EKS cluster OIDC issuers: "+err.Error())}
	}
	iamClient := r.options.IAMClientFactory(iamCfg)

	resolved := map[string]string{}
	var gaps []ci.Gap
	for cluster := range ambiguousClusters {
		gaps = append(gaps, awsGap("aws_eks_cluster_name_ambiguous", cluster, "Multiple consumers report this cluster name with different accounts/regions; refusing to guess which one to query"))
	}
	for cluster, location := range locations {
		region := location.Region
		if region == "" {
			gaps = append(gaps, awsGap("aws_eks_cluster_region_unresolved", cluster, "No region is known for this cluster; refusing to query a default/fallback region"))
			continue
		}
		if err := r.budget.take(); err != nil {
			gaps = append(gaps, awsGap("aws_request_budget_exceeded", cluster, "Request budget exhausted before EKS issuer resolution completed"))
			continue
		}
		eksCfg, err := r.assumedConfigForRegion(ctx, principal.Account, region)
		if err != nil {
			gaps = append(gaps, awsGap("aws_eks_issuer_unavailable", cluster, "Could not assume role to resolve this cluster's EKS OIDC issuer: "+err.Error()))
			continue
		}
		eksClient := r.options.EKSClientFactory(eksCfg)
		describeOut, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(cluster)})
		if err != nil {
			gaps = append(gaps, awsGap("aws_eks_cluster_unavailable", cluster, "EKS cluster OIDC issuer could not be retrieved: "+err.Error()))
			continue
		}
		if describeOut.Cluster == nil || describeOut.Cluster.Identity == nil || describeOut.Cluster.Identity.Oidc == nil {
			gaps = append(gaps, awsGap("aws_eks_cluster_oidc_missing", cluster, "EKS cluster has no OIDC identity provider configured"))
			continue
		}
		issuer := aws.ToString(describeOut.Cluster.Identity.Oidc.Issuer)
		if issuer == "" {
			continue
		}
		resolved["aws_eks_oidc_issuer:"+cluster] = issuer
		providerARN, found, providerGaps := r.resolveOIDCProviderARN(ctx, iamClient, issuer, cluster)
		gaps = append(gaps, providerGaps...)
		if found {
			resolved["aws_eks_oidc_provider_arn:"+cluster] = providerARN
		}
	}
	return resolved, gaps
}

// resolveOIDCProviderARN finds the IAM OIDC provider registered for issuer.
// ListOpenIDConnectProviders is not paginated by the API; a single call
// always returns the account's full provider list.
func (r *awsReader) resolveOIDCProviderARN(ctx context.Context, iamClient awsIAMReadAPI, issuer, scope string) (string, bool, []ci.Gap) {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if err := r.budget.take(); err != nil {
		return "", false, []ci.Gap{awsGap("aws_request_budget_exceeded", scope, "Request budget exhausted before OIDC providers were listed")}
	}
	out, err := iamClient.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return "", false, []ci.Gap{awsGap("aws_eks_oidc_provider_list_failed", scope, "Listing IAM OIDC providers did not complete: "+err.Error())}
	}
	for _, entry := range out.OpenIDConnectProviderList {
		arn := aws.ToString(entry.Arn)
		if strings.HasSuffix(arn, "/"+host) || strings.HasSuffix(arn, host) {
			return arn, true, nil
		}
	}
	return "", false, nil
}
