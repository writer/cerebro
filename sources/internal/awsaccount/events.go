package awsaccount

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/writer/cerebro/internal/primitives"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

type eventSpec struct {
	ID         string
	Kind       string
	SchemaRef  string
	Payload    []byte
	Attributes map[string]string
	OccurredAt time.Time
}

func accountSummaryEvent(accountID string, summary AccountSummary) (eventSpec, error) {
	attributes := map[string]string{
		"domain":                   accountID,
		"family":                   familyAccountSummary,
		"resource_id":              accountID,
		"resource_name":            accountID,
		"resource_type":            "aws_account",
		"root_access_keys_present": boolString(summary.SummaryMap["AccountAccessKeysPresent"] > 0),
		"root_mfa_enabled":         boolString(summary.SummaryMap["AccountMFAEnabled"] > 0),
	}
	for key, value := range summary.SummaryMap {
		attributes["summary_"+attributeKey(key)] = strconv.FormatInt(int64(value), 10)
	}
	payload, err := json.Marshal(map[string]any{"account_id": accountID, "summary": summary.SummaryMap})
	if err != nil {
		return eventSpec{}, err
	}
	return eventSpec{ID: "aws-iam-account-summary-" + accountID, Kind: "aws.iam_account_summary", SchemaRef: "aws/iam_account_summary/v1", Payload: payload, Attributes: attributes, OccurredAt: time.Now().UTC()}, nil
}

func accountPasswordPolicyEvent(accountID string, record AccountPasswordPolicy) (eventSpec, error) {
	attributes := map[string]string{
		"domain":         accountID,
		"family":         familyAccountPasswordPolicy,
		"policy_present": boolString(record.Present),
		"resource_id":    accountID,
		"resource_name":  accountID,
		"resource_type":  "aws_iam_account_password_policy",
	}
	if policy := record.Policy; policy != nil {
		attributes["allow_users_to_change_password"] = boolString(policy.AllowUsersToChangePassword)
		attributes["expire_passwords"] = boolString(policy.ExpirePasswords)
		attributes["hard_expiry"] = boolString(awssdk.ToBool(policy.HardExpiry))
		attributes["max_password_age_days"] = int32String(policy.MaxPasswordAge)
		attributes["minimum_password_length"] = int32String(policy.MinimumPasswordLength)
		attributes["password_reuse_prevention"] = int32String(policy.PasswordReusePrevention)
		attributes["require_lowercase_characters"] = boolString(policy.RequireLowercaseCharacters)
		attributes["require_numbers"] = boolString(policy.RequireNumbers)
		attributes["require_symbols"] = boolString(policy.RequireSymbols)
		attributes["require_uppercase_characters"] = boolString(policy.RequireUppercaseCharacters)
	}
	payload, err := json.Marshal(map[string]any{"account_id": accountID, "policy_present": record.Present, "password_policy": record.Policy})
	if err != nil {
		return eventSpec{}, err
	}
	return eventSpec{ID: "aws-iam-account-password-policy-" + accountID, Kind: "aws.iam_account_password_policy", SchemaRef: "aws/iam_account_password_policy/v1", Payload: payload, Attributes: attributes, OccurredAt: time.Now().UTC()}, nil
}

func credentialReportEvent(accountID string, row CredentialReportRow) (eventSpec, error) {
	user := firstNonEmpty(row.Values["user"], row.Values["arn"], accountID)
	attributes := map[string]string{
		"access_key_1_active":       row.Values["access_key_1_active"],
		"access_key_1_last_rotated": row.Values["access_key_1_last_rotated"],
		"access_key_2_active":       row.Values["access_key_2_active"],
		"access_key_2_last_rotated": row.Values["access_key_2_last_rotated"],
		"arn":                       row.Values["arn"],
		"domain":                    accountID,
		"family":                    familyCredentialReport,
		"mfa_active":                row.Values["mfa_active"],
		"password_enabled":          row.Values["password_enabled"],
		"password_last_changed":     row.Values["password_last_changed"],
		"password_last_used":        row.Values["password_last_used"],
		"principal_type":            map[bool]string{true: "root", false: "user"}[user == "<root_account>"],
		"report_format":             row.ReportFormat,
		"resource_id":               firstNonEmpty(row.Values["arn"], user),
		"resource_name":             user,
		"resource_type":             "aws_iam_credential_report_row",
		"subject_email":             emailLike(user),
		"subject_id":                user,
		"subject_type":              "user",
		"user_name":                 user,
	}
	addTime(attributes, "generated_at", row.GeneratedTime)
	payload, err := json.Marshal(map[string]any{"account_id": accountID, "generated_at": row.GeneratedTime, "report_format": row.ReportFormat, "row": row.Values})
	if err != nil {
		return eventSpec{}, err
	}
	return eventSpec{ID: "aws-iam-credential-report-" + firstNonEmpty(row.Values["arn"], user), Kind: "aws.iam_credential_report", SchemaRef: "aws/iam_credential_report/v1", Payload: payload, Attributes: attributes, OccurredAt: firstTime(row.GeneratedTime)}, nil
}

func accountSummaryURN(accountID string, _ AccountSummary) string {
	return fmt.Sprintf("urn:cerebro:%s:iam_account_summary:%s", accountID, accountID)
}

func accountPasswordPolicyURN(accountID string, _ AccountPasswordPolicy) string {
	return fmt.Sprintf("urn:cerebro:%s:iam_account_password_policy:%s", accountID, accountID)
}

func credentialReportURN(accountID string, row CredentialReportRow) string {
	return fmt.Sprintf("urn:cerebro:%s:iam_credential_report:%s", accountID, firstNonEmpty(row.Values["arn"], row.Values["user"], accountID))
}

func event(accountID string, spec eventSpec) *primitives.Event {
	trimEmptyAttributes(spec.Attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(spec.ID),
		TenantId:   accountID,
		SourceId:   "aws",
		Kind:       spec.Kind,
		OccurredAt: timestamppb.New(spec.OccurredAt.UTC()),
		SchemaRef:  spec.SchemaRef,
		Payload:    spec.Payload,
		Attributes: spec.Attributes,
	}
}

func attributeKey(value string) string {
	var builder strings.Builder
	var previousUnderscore bool
	for index, char := range value {
		switch {
		case char >= 'A' && char <= 'Z':
			if index > 0 && !previousUnderscore {
				builder.WriteByte('_')
			}
			builder.WriteRune(char + ('a' - 'A'))
			previousUnderscore = false
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			builder.WriteRune(char)
			previousUnderscore = false
		default:
			if !previousUnderscore {
				builder.WriteByte('_')
			}
			previousUnderscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func addTime(attributes map[string]string, key string, value *time.Time) {
	if value != nil && !value.IsZero() {
		attributes[key] = value.UTC().Format(time.RFC3339)
	}
}

func emailLike(value string) string {
	return strings.ToLower(strings.TrimSpace(emailPattern.FindString(strings.TrimSpace(value))))
}

func boolString(value bool) string {
	return strconv.FormatBool(value)
}

func int32String(value *int32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(int64(*value), 10)
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}

func sanitizeEventID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "event"
	}
	replacer := strings.NewReplacer(" ", "-", "\t", "-", "\n", "-", "\r", "-", "/", "-", ":", "-", "#", "-")
	return replacer.Replace(value)
}
