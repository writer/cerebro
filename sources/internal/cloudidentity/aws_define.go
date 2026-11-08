package cloudidentitysource

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

var awsManagedPolicyARNPattern = regexp.MustCompile(`^arn:aws[a-zA-Z0-9-]*:iam::(aws|\d{12}):policy/`)

func awsManagedPolicyAccount(arn string) (string, bool) {
	match := awsManagedPolicyARNPattern.FindStringSubmatch(strings.TrimSpace(arn))
	if match == nil {
		return "", false
	}
	return match[1], true
}

// expandServiceWildcard resolves a trailing-"*" service pattern (bare "*"
// matches every service) against the live, cached AWS Service Reference
// index, returning the matching service prefixes in deterministic order.
func (r *awsReader) expandServiceWildcard(ctx context.Context, prefix string) ([]string, error) {
	index, err := r.serviceReferenceIndex(ctx)
	if err != nil {
		return nil, err
	}
	matched := make([]string, 0, len(index))
	for service := range index {
		if strings.HasPrefix(service, prefix) {
			matched = append(matched, service)
		}
	}
	sort.Strings(matched)
	return matched, nil
}

// Define implements ci.CloudReader. It resolves AWSServices against the
// official, live AWS Service Reference (action/resource-type/operation
// definitions) and AWSPolicies against live IAM (default managed-policy
// versions). GCPRoles is ignored: it belongs to the GCP adapter.
//
// A trailing-"*" entry (including a bare "*", meaning every service) is a
// real least-privilege case — typically Action:"*" in a reviewed grant — and
// is never refused outright: it is expanded against the live, cached SAR
// index and every matching service is fetched up to the shared request
// budget. If the budget is exhausted mid-expansion, the definitions
// collected so far are returned with Complete=false and a scoped gap
// documenting the partial subset; nothing is silently skipped or faked.
func (r *awsReader) Define(ctx context.Context, request ci.DefinitionRequest) (ci.Definitions, error) {
	now := r.clock().UTC()
	var actions []ci.ActionDefinition
	var operations []ci.OperationDefinition
	var policies []ci.ManagedPolicy
	var gaps []ci.Gap
	complete := true
	awsServiceCatalogComplete := false

	for _, service := range request.AWSServices {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		if strings.HasSuffix(service, "*") {
			prefix := strings.TrimSuffix(service, "*")
			matched, err := r.expandServiceWildcard(ctx, prefix)
			if err != nil {
				gaps = append(gaps, awsGap("aws_definitions_wildcard_index_unavailable", service, "Could not enumerate services for wildcard expansion against the AWS Service Reference index: "+err.Error()))
				complete = false
				continue
			}
			if len(matched) == 0 {
				gaps = append(gaps, awsGap("aws_definitions_wildcard_no_match", service, "No AWS service in the official Service Reference index matched this wildcard prefix"))
				continue
			}
			budgetExhausted := false
			reached := 0
			for _, svc := range matched {
				svcActions, svcOps, svcGaps, err := r.serviceDefinitions(ctx, svc, now)
				if err != nil {
					if errors.Is(err, errAWSRequestBudgetExceeded) {
						budgetExhausted = true
						break
					}
					gaps = append(gaps, awsGap("aws_service_definitions_unavailable", svc, "AWS Service Reference definitions could not be retrieved: "+err.Error()))
					complete = false
					continue
				}
				actions = append(actions, svcActions...)
				operations = append(operations, svcOps...)
				// svcGaps (unknown operation mapping, missing authorized
				// actions, FAS/SSE-KMS dependent-permission disclosure) are
				// recorded for visibility but no longer flip Complete=false:
				// per-operation OperationDefinition.DependenciesComplete is
				// the authoritative "is this permission set exhaustive"
				// signal a validator checks before trusting a called
				// operation's Permissions as a removal basis.
				gaps = append(gaps, svcGaps...)
				reached++
			}
			if budgetExhausted {
				gaps = append(gaps, awsGap("aws_definitions_wildcard_budget_exhausted", service, fmt.Sprintf("Request budget exhausted expanding wildcard %q: resolved %d of %d matching services; definitions are a partial subset, not an empty or complete set", service, reached, len(matched))))
				complete = false
			} else if prefix == "" && reached == len(matched) {
				// A bare "*" service request that expanded the full Service
				// Reference index and fetched every listed service without
				// a single failure: Actions now genuinely contains every
				// action of every published service.
				awsServiceCatalogComplete = true
			}
			continue
		}
		svcActions, svcOps, svcGaps, err := r.serviceDefinitions(ctx, service, now)
		if err != nil {
			gaps = append(gaps, awsGap("aws_service_definitions_unavailable", service, "AWS Service Reference definitions could not be retrieved: "+err.Error()))
			complete = false
			continue
		}
		actions = append(actions, svcActions...)
		operations = append(operations, svcOps...)
		gaps = append(gaps, svcGaps...)
	}

	for _, arn := range request.AWSPolicies {
		arn = strings.TrimSpace(arn)
		if arn == "" {
			continue
		}
		account, ok := awsManagedPolicyAccount(arn)
		if !ok {
			// Not an AWS IAM policy ARN; belongs to another provider's
			// Grant.Role reference, not ours to resolve.
			continue
		}
		var cfg aws.Config
		var err error
		if account == "aws" {
			cfg = r.options.Config
		} else {
			cfg, err = r.assumedConfig(ctx, account)
		}
		if err != nil {
			gaps = append(gaps, awsGap("aws_policy_account_unavailable", arn, "Could not assume role to resolve managed policy account: "+err.Error()))
			complete = false
			continue
		}
		iamClient := r.options.IAMClientFactory(cfg)
		managed, err := r.resolveManagedPolicy(ctx, iamClient, arn, now)
		if err != nil {
			gaps = append(gaps, awsGap("aws_managed_policy_unavailable", arn, err.Error()))
			complete = false
			continue
		}
		policies = append(policies, managed)
	}

	// Digest is intentionally left unset: Assess validates Definitions.Digest
	// against a canonical sorted-field hash (cloudidentity.MergeDefinitions'
	// shape), which the collection pipeline computes after merging this
	// result with Observation.Definitions. Leaving it empty here is never
	// flagged as a mismatch (per IamAssessment).
	definitions := ci.Definitions{Actions: actions, Operations: operations, Policies: policies, Complete: complete, AWSServiceCatalogComplete: awsServiceCatalogComplete, Gaps: gaps}
	return definitions, nil
}
