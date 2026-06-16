package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsIAMPolicy struct {
	Policy         iamtypes.Policy
	DefaultVersion *iamtypes.PolicyVersion
	Document       map[string]any
	Actions        []string
	Resources      []string
	AllowsAdmin    bool
}

func listIAMPolicies(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsIAMPolicy, string, error) {
	out, err := clients.iam.ListPolicies(ctx, &iam.ListPoliciesInput{
		Marker:   stringPtr(cursor),
		MaxItems: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 1000)),
		Scope:    iamtypes.PolicyScopeTypeLocal,
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsIAMPolicy, 0, len(out.Policies))
	for _, summary := range out.Policies {
		record := awsIAMPolicy{Policy: summary}
		arn := awssdk.ToString(summary.Arn)
		if arn != "" {
			detail, err := clients.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awssdk.String(arn)})
			if optionalAWSError(err, "NoSuchEntity") {
				continue
			}
			if err != nil {
				return nil, "", err
			}
			if detail.Policy != nil {
				record.Policy = *detail.Policy
			}
		}
		versionID := awssdk.ToString(record.Policy.DefaultVersionId)
		if arn != "" && versionID != "" {
			version, err := clients.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: awssdk.String(arn), VersionId: awssdk.String(versionID)})
			if optionalAWSError(err, "NoSuchEntity") {
				continue
			}
			if err != nil {
				return nil, "", err
			}
			if version.PolicyVersion != nil {
				record.DefaultVersion = version.PolicyVersion
				documentText := decodeIAMPolicyDocument(awssdk.ToString(version.PolicyVersion.Document))
				record.Document = parseIAMPolicyDocument(documentText)
				record.Actions = policyDocumentActions(documentText)
				record.Resources = policyDocumentResources(record.Document)
				record.AllowsAdmin = policyDocumentAllowsAdmin(record.Document)
			}
		}
		records = append(records, record)
	}
	return records, nextMarker(out.IsTruncated, out.Marker), nil
}

func iamPolicyEvent(settings settings, record awsIAMPolicy) (*primitives.Event, error) {
	policy := record.Policy
	policyARN := awssdk.ToString(policy.Arn)
	policyName := awssdk.ToString(policy.PolicyName)
	policyID := awssdk.ToString(policy.PolicyId)
	attributes := commonCloudAssetAttributes(settings, "global", familyIAMPolicy, policyARN, policyName, "iam_policy", iamTagMap(policy.Tags))
	attributes["actions"] = strings.Join(record.Actions, ",")
	attributes["allows_admin_star"] = boolString(record.AllowsAdmin)
	attributes["arn"] = policyARN
	attributes["attachment_count"] = strconv.Itoa(int(awssdk.ToInt32(policy.AttachmentCount)))
	attributes["default_version_id"] = awssdk.ToString(policy.DefaultVersionId)
	attributes["is_attachable"] = boolString(policy.IsAttachable)
	attributes["path"] = awssdk.ToString(policy.Path)
	attributes["permissions_boundary_usage_count"] = strconv.Itoa(int(awssdk.ToInt32(policy.PermissionsBoundaryUsageCount)))
	attributes["policy_arn"] = policyARN
	attributes["policy_id"] = policyID
	attributes["policy_name"] = policyName
	attributes["policy_resource_type"] = "aws::iam::policy"
	attributes["resources"] = strings.Join(record.Resources, ",")
	attributes["resource_arn"] = policyARN
	attributes["scope"] = settings.accountID
	addTimeAttribute(attributes, "created_at", policy.CreateDate)
	addTimeAttribute(attributes, "updated_at", policy.UpdateDate)
	payload, err := json.Marshal(map[string]any{
		"account_id":           settings.accountID,
		"region":               "global",
		"policy":               policy,
		"policy_document":      record.Document,
		"default_version":      record.DefaultVersion,
		"actions":              record.Actions,
		"resources":            record.Resources,
		"allows_admin_star":    record.AllowsAdmin,
		"policy_resource_type": "aws::iam::policy",
	})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-policy-"+firstNonEmpty(policyID, policyARN, policyName), "aws.iam_policy", "aws/iam_policy/v1", payload, attributes, firstTime(policy.UpdateDate, policy.CreateDate))
}

func decodeIAMPolicyDocument(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if decoded, err := url.QueryUnescape(raw); err == nil {
		return decoded
	}
	return raw
}

func parseIAMPolicyDocument(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}
	return document
}

func policyDocumentResources(document map[string]any) []string {
	if len(document) == 0 {
		return nil
	}
	return sortedUniqueStrings(policyDocumentStatementValues(document["Statement"], "Resource"))
}

func policyDocumentAllowsAdmin(document map[string]any) bool {
	for _, statement := range policyDocumentStatements(document["Statement"]) {
		if effect := strings.TrimSpace(stringScalar(statement["Effect"])); !strings.EqualFold(effect, "Allow") {
			continue
		}
		if containsExactString(policyDocumentStatementValues(statement, "Action"), "*") && containsExactString(policyDocumentStatementValues(statement, "Resource"), "*") {
			return true
		}
	}
	return false
}

func policyDocumentStatements(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		statements := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			statements = append(statements, policyDocumentStatements(item)...)
		}
		return statements
	case map[string]any:
		return []map[string]any{typed}
	default:
		return nil
	}
}

func policyDocumentStatementValues(value any, key string) []string {
	switch typed := value.(type) {
	case []any:
		values := make([]string, 0)
		for _, item := range typed {
			values = append(values, policyDocumentStatementValues(item, key)...)
		}
		return values
	case map[string]any:
		return stringList(typed[key])
	default:
		return nil
	}
}

func containsExactString(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

func stringScalar(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}
