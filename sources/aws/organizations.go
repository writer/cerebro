package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsOrganizationsAccount struct {
	Account organizationstypes.Account
	Parent  organizationstypes.Parent
}

type awsOrganizationsOrganizationalUnit struct {
	OrganizationalUnit organizationstypes.OrganizationalUnit
	Parent             organizationstypes.Parent
}

type awsOrganizationsPolicy struct {
	Summary organizationstypes.PolicySummary
	Content string
	Targets []organizationstypes.PolicyTargetSummary
}

func listOrganizationsAccounts(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsAccount, string, error) {
	out, err := clients.organizations.ListAccounts(ctx, &organizations.ListAccountsInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 20))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsOrganizationsAccount, 0, len(out.Accounts))
	for _, account := range out.Accounts {
		record := awsOrganizationsAccount{Account: account}
		if parent, err := organizationsParent(ctx, clients, awssdk.ToString(account.Id)); err != nil {
			return nil, "", fmt.Errorf("list parents for organizations account %q: %w", awssdk.ToString(account.Id), err)
		} else {
			record.Parent = parent
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listOrganizationsRoots(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]organizationstypes.Root, string, error) {
	out, err := clients.organizations.ListRoots(ctx, &organizations.ListRootsInput{
		NextToken:  stringPtr(cursor),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 20))),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Roots, awssdk.ToString(out.NextToken), nil
}

func listOrganizationsOrganizationalUnits(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsOrganizationalUnit, string, error) {
	records, err := listAllOrganizationsOrganizationalUnits(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	page, next, err := pageOrganizationsRecords(records, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	return page, next, nil
}

func listAllOrganizationsOrganizationalUnits(ctx context.Context, clients awsClients) ([]awsOrganizationsOrganizationalUnit, error) {
	roots, err := listAllOrganizationsRoots(ctx, clients)
	if err != nil {
		return nil, err
	}
	var records []awsOrganizationsOrganizationalUnit
	queue := make([]organizationstypes.Parent, 0, len(roots))
	for _, root := range roots {
		if id := awssdk.ToString(root.Id); id != "" {
			queue = append(queue, organizationstypes.Parent{Id: awssdk.String(id), Type: organizationstypes.ParentTypeRoot})
		}
	}
	for len(queue) != 0 {
		parent := queue[0]
		queue = queue[1:]
		var next *string
		for {
			out, err := clients.organizations.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{
				ParentId:   parent.Id,
				NextToken:  next,
				MaxResults: awssdk.Int32(20),
			})
			if err != nil {
				return nil, fmt.Errorf("list organizations organizational units for parent %q: %w", awssdk.ToString(parent.Id), err)
			}
			for _, ou := range out.OrganizationalUnits {
				record := awsOrganizationsOrganizationalUnit{OrganizationalUnit: ou, Parent: parent}
				records = append(records, record)
				if id := awssdk.ToString(ou.Id); id != "" {
					queue = append(queue, organizationstypes.Parent{Id: awssdk.String(id), Type: organizationstypes.ParentTypeOrganizationalUnit})
				}
			}
			if awssdk.ToString(out.NextToken) == "" {
				break
			}
			next = out.NextToken
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		return awssdk.ToString(records[i].OrganizationalUnit.Id) < awssdk.ToString(records[j].OrganizationalUnit.Id)
	})
	return records, nil
}

func listAllOrganizationsRoots(ctx context.Context, clients awsClients) ([]organizationstypes.Root, error) {
	var roots []organizationstypes.Root
	var next string
	for {
		page, token, err := listOrganizationsRoots(ctx, clients, settings{}, next, 20)
		if err != nil {
			return nil, err
		}
		roots = append(roots, page...)
		if token == "" {
			return roots, nil
		}
		next = token
	}
}

func listOrganizationsPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsOrganizationsPolicy, string, error) {
	records, err := listAllOrganizationsPolicies(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	page, next, err := pageOrganizationsRecords(records, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	return page, next, nil
}

func listAllOrganizationsPolicies(ctx context.Context, clients awsClients) ([]awsOrganizationsPolicy, error) {
	var records []awsOrganizationsPolicy
	for _, policyType := range organizationsPolicyTypes() {
		var next *string
		for {
			out, err := clients.organizations.ListPolicies(ctx, &organizations.ListPoliciesInput{
				Filter:     policyType,
				NextToken:  next,
				MaxResults: awssdk.Int32(20),
			})
			if err != nil {
				return nil, fmt.Errorf("list organizations policies %s: %w", policyType, err)
			}
			for _, summary := range out.Policies {
				record := awsOrganizationsPolicy{Summary: summary}
				if detail, err := clients.organizations.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: summary.Id}); err != nil {
					return nil, fmt.Errorf("describe organizations policy %q: %w", awssdk.ToString(summary.Id), err)
				} else if detail.Policy != nil {
					record.Content = awssdk.ToString(detail.Policy.Content)
					if detail.Policy.PolicySummary != nil {
						record.Summary = *detail.Policy.PolicySummary
					}
				}
				targets, err := organizationsPolicyTargets(ctx, clients, awssdk.ToString(record.Summary.Id))
				if err != nil {
					return nil, err
				}
				record.Targets = targets
				records = append(records, record)
			}
			if awssdk.ToString(out.NextToken) == "" {
				break
			}
			next = out.NextToken
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		return awssdk.ToString(records[i].Summary.Id) < awssdk.ToString(records[j].Summary.Id)
	})
	return records, nil
}

func organizationsAccountEvent(settings settings, record awsOrganizationsAccount) (*primitives.Event, error) {
	account := record.Account
	accountID := awssdk.ToString(account.Id)
	arn := awssdk.ToString(account.Arn)
	attributes := organizationsResourceAttributes(settings, familyOrganizationsAccount, firstNonEmpty(accountID, arn), awssdk.ToString(account.Name), "organizations_account")
	attributes["account_arn"] = arn
	attributes["account_email"] = awssdk.ToString(account.Email)
	attributes["account_id"] = accountID
	attributes["account_name"] = awssdk.ToString(account.Name)
	attributes["joined_method"] = string(account.JoinedMethod)
	attributes["parent_id"] = awssdk.ToString(record.Parent.Id)
	attributes["parent_type"] = string(record.Parent.Type)
	attributes["relationship"] = "member_of"
	attributes["state"] = string(account.State)
	attributes["status"] = string(account.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "account": account, "parent": record.Parent})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-account-"+firstNonEmpty(accountID, arn), "aws.organizations_account", "aws/organizations_account/v1", payload, attributes, firstTime(account.JoinedTimestamp))
}

func organizationsOrganizationalUnitEvent(settings settings, record awsOrganizationsOrganizationalUnit) (*primitives.Event, error) {
	ou := record.OrganizationalUnit
	ouID := awssdk.ToString(ou.Id)
	arn := awssdk.ToString(ou.Arn)
	attributes := organizationsResourceAttributes(settings, familyOrganizationsOU, firstNonEmpty(ouID, arn), awssdk.ToString(ou.Name), "organizations_organizational_unit")
	attributes["ou_arn"] = arn
	attributes["ou_id"] = ouID
	attributes["ou_name"] = awssdk.ToString(ou.Name)
	attributes["parent_id"] = awssdk.ToString(record.Parent.Id)
	attributes["parent_type"] = string(record.Parent.Type)
	attributes["relationship"] = "belongs_to"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "organizational_unit": ou, "parent": record.Parent})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-ou-"+firstNonEmpty(ouID, arn), "aws.organizations_organizational_unit", "aws/organizations_organizational_unit/v1", payload, attributes, time.Now().UTC())
}

func organizationsRootEvent(settings settings, root organizationstypes.Root) (*primitives.Event, error) {
	rootID := awssdk.ToString(root.Id)
	arn := awssdk.ToString(root.Arn)
	attributes := organizationsResourceAttributes(settings, familyOrganizationsRoot, firstNonEmpty(rootID, arn), awssdk.ToString(root.Name), "organizations_root")
	attributes["policy_types"] = strings.Join(organizationsRootPolicyTypes(root), ",")
	attributes["root_arn"] = arn
	attributes["root_id"] = rootID
	attributes["root_name"] = awssdk.ToString(root.Name)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "root": root})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-root-"+firstNonEmpty(rootID, arn), "aws.organizations_root", "aws/organizations_root/v1", payload, attributes, time.Now().UTC())
}

func organizationsPolicyEvent(settings settings, policy awsOrganizationsPolicy) (*primitives.Event, error) {
	summary := policy.Summary
	policyID := awssdk.ToString(summary.Id)
	arn := awssdk.ToString(summary.Arn)
	attributes := organizationsResourceAttributes(settings, familyOrganizationsPolicy, firstNonEmpty(policyID, arn), awssdk.ToString(summary.Name), "organizations_policy")
	attributes["aws_managed"] = boolString(summary.AwsManaged)
	attributes["description"] = awssdk.ToString(summary.Description)
	attributes["policy_arn"] = arn
	attributes["policy_content"] = policy.Content
	attributes["policy_id"] = policyID
	attributes["policy_name"] = awssdk.ToString(summary.Name)
	attributes["policy_type"] = string(summary.Type)
	attributes["relationship"] = "attached_to"
	attributes["target_arns"] = strings.Join(organizationsTargetARNs(policy.Targets), ",")
	attributes["target_ids"] = strings.Join(organizationsTargetIDs(policy.Targets), ",")
	attributes["target_names"] = strings.Join(organizationsTargetNames(policy.Targets), ",")
	attributes["target_types"] = strings.Join(organizationsTargetTypes(policy.Targets), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "policy": summary, "content": policy.Content, "targets": policy.Targets})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-organizations-policy-"+firstNonEmpty(policyID, arn), "aws.organizations_policy", "aws/organizations_policy/v1", payload, attributes, time.Now().UTC())
}

func organizationsParent(ctx context.Context, clients awsClients, childID string) (organizationstypes.Parent, error) {
	if strings.TrimSpace(childID) == "" {
		return organizationstypes.Parent{}, nil
	}
	out, err := clients.organizations.ListParents(ctx, &organizations.ListParentsInput{ChildId: awssdk.String(childID)})
	if err != nil {
		return organizationstypes.Parent{}, err
	}
	if len(out.Parents) == 0 {
		return organizationstypes.Parent{}, nil
	}
	return out.Parents[0], nil
}

func organizationsPolicyTargets(ctx context.Context, clients awsClients, policyID string) ([]organizationstypes.PolicyTargetSummary, error) {
	if strings.TrimSpace(policyID) == "" {
		return nil, nil
	}
	var targets []organizationstypes.PolicyTargetSummary
	var next *string
	for {
		out, err := clients.organizations.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{
			PolicyId:   awssdk.String(policyID),
			NextToken:  next,
			MaxResults: awssdk.Int32(20),
		})
		if err != nil {
			return nil, fmt.Errorf("list targets for organizations policy %q: %w", policyID, err)
		}
		targets = append(targets, out.Targets...)
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	return targets, nil
}

func organizationsPolicyTypes() []organizationstypes.PolicyType {
	return []organizationstypes.PolicyType{
		organizationstypes.PolicyType("AISERVICES_OPT_OUT_POLICY"),
		organizationstypes.PolicyType("BACKUP_POLICY"),
		organizationstypes.PolicyType("RESOURCE_CONTROL_POLICY"),
		organizationstypes.PolicyType("SERVICE_CONTROL_POLICY"),
		organizationstypes.PolicyType("TAG_POLICY"),
	}
}

func organizationsResourceAttributes(settings settings, family string, resourceID string, resourceName string, resourceType string) map[string]string {
	return map[string]string{
		"domain":            settings.accountID,
		"family":            family,
		"region":            "global",
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "aws",
		"resource_type":     resourceType,
	}
}

func pageOrganizationsRecords[T any](records []T, cursor string, limit int) ([]T, string, error) {
	offset := 0
	if strings.TrimSpace(cursor) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(cursor))
		if err != nil {
			return nil, "", fmt.Errorf("parse organizations cursor: %w", err)
		}
		if parsed < 0 || parsed > len(records) {
			return nil, "", fmt.Errorf("organizations cursor offset %d is out of range", parsed)
		}
		offset = parsed
	}
	pageSize := boundedAWSPageSize(limit, 1, maxPageSize)
	if offset+pageSize >= len(records) {
		return records[offset:], "", nil
	}
	return records[offset : offset+pageSize], strconv.Itoa(offset + pageSize), nil
}

func organizationsRootPolicyTypes(root organizationstypes.Root) []string {
	values := make([]string, 0, len(root.PolicyTypes))
	for _, policyType := range root.PolicyTypes {
		values = append(values, string(policyType.Type)+":"+string(policyType.Status))
	}
	sort.Strings(values)
	return values
}

func organizationsTargetIDs(targets []organizationstypes.PolicyTargetSummary) []string {
	return organizationsTargetField(targets, func(target organizationstypes.PolicyTargetSummary) string {
		return awssdk.ToString(target.TargetId)
	})
}

func organizationsTargetARNs(targets []organizationstypes.PolicyTargetSummary) []string {
	return organizationsTargetField(targets, func(target organizationstypes.PolicyTargetSummary) string {
		return awssdk.ToString(target.Arn)
	})
}

func organizationsTargetNames(targets []organizationstypes.PolicyTargetSummary) []string {
	return organizationsTargetField(targets, func(target organizationstypes.PolicyTargetSummary) string {
		return awssdk.ToString(target.Name)
	})
}

func organizationsTargetTypes(targets []organizationstypes.PolicyTargetSummary) []string {
	return organizationsTargetField(targets, func(target organizationstypes.PolicyTargetSummary) string {
		return string(target.Type)
	})
}

func organizationsTargetField(targets []organizationstypes.PolicyTargetSummary, extract func(organizationstypes.PolicyTargetSummary) string) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, strings.TrimSpace(extract(target)))
	}
	return values
}
