package awsaccount

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	familyAccountPasswordPolicy = "iam_account_password_policy"
	familyAccountSummary        = "iam_account_summary"
	familyCredentialReport      = "iam_credential_report" // #nosec G101 -- source family identifier, not credential material.

	credentialReportGenerateAttempts = 5
	credentialReportGenerateDelay    = 100 * time.Millisecond
)

var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

type iamClient interface {
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

type AccountSummary struct {
	SummaryMap map[string]int32
}

type AccountPasswordPolicy struct {
	Present bool
	Policy  *iamtypes.PasswordPolicy
}

type CredentialReportRow struct {
	GeneratedTime *time.Time
	ReportFormat  string
	Values        map[string]string
}

type eventSpec struct {
	ID         string
	Kind       string
	SchemaRef  string
	Payload    []byte
	Attributes map[string]string
	OccurredAt time.Time
}

func Families[S any, C any](clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any, accountID func(S) string) []sourcecdk.Family[S] {
	return []sourcecdk.Family[S]{
		family(clientFactory, iamFromClients, accountID, familyAccountSummary, "aws iam account summary", listAccountSummary, accountSummaryEvent, accountSummaryURN),
		family(clientFactory, iamFromClients, accountID, familyAccountPasswordPolicy, "aws iam account password policy", listAccountPasswordPolicy, accountPasswordPolicyEvent, accountPasswordPolicyURN),
		family(clientFactory, iamFromClients, accountID, familyCredentialReport, "aws iam credential report", listCredentialReport, credentialReportEvent, credentialReportURN),
	}
}

func family[S any, C any, T any](clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any, accountID func(S) string, name string, label string, list func(context.Context, iamClient) ([]T, error), build func(string, T) (eventSpec, error), urn func(string, T) string) sourcecdk.Family[S] {
	return sourcecdk.Family[S]{
		Name: name,
		Check: func(ctx context.Context, settings S) error {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return err
			}
			_, err = list(ctx, client)
			return err
		},
		Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return nil, err
			}
			records, err := list(ctx, client)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			urns := make([]sourcecdk.URN, 0, len(records))
			for _, record := range records {
				parsed, err := sourcecdk.ParseURN(urn(accountID(settings), record))
				if err != nil {
					return nil, err
				}
				urns = append(urns, parsed)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := list(ctx, client)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			events := make([]*primitives.Event, 0, len(records))
			for _, record := range records {
				spec, err := build(accountID(settings), record)
				if err != nil {
					return sourcecdk.Pull{}, err
				}
				events = append(events, event(accountID(settings), spec))
			}
			return sourcecdk.Pull{Events: events}, nil
		},
	}
}

func resolveIAMClient[S any, C any](ctx context.Context, settings S, clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any) (iamClient, error) {
	clients, err := clientFactory(ctx, settings)
	if err != nil {
		return nil, err
	}
	client, ok := iamFromClients(clients).(iamClient)
	if !ok {
		return nil, fmt.Errorf("aws iam client does not support account posture APIs")
	}
	return client, nil
}

func listAccountSummary(ctx context.Context, client iamClient) ([]AccountSummary, error) {
	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	return []AccountSummary{{SummaryMap: out.SummaryMap}}, nil
}

func listAccountPasswordPolicy(ctx context.Context, client iamClient) ([]AccountPasswordPolicy, error) {
	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var missing *iamtypes.NoSuchEntityException
		if errors.As(err, &missing) {
			return []AccountPasswordPolicy{{Present: false}}, nil
		}
		return nil, err
	}
	return []AccountPasswordPolicy{{Present: out.PasswordPolicy != nil, Policy: out.PasswordPolicy}}, nil
}

func listCredentialReport(ctx context.Context, client iamClient) ([]CredentialReportRow, error) {
	out, ready, err := getCredentialReport(ctx, client)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	rows, err := parseCredentialReport(out.Content)
	if err != nil {
		return nil, err
	}
	records := make([]CredentialReportRow, 0, len(rows))
	for _, row := range rows {
		records = append(records, CredentialReportRow{GeneratedTime: out.GeneratedTime, ReportFormat: string(out.ReportFormat), Values: row})
	}
	return records, nil
}

func getCredentialReport(ctx context.Context, client iamClient) (*iam.GetCredentialReportOutput, bool, error) {
	for attempt := 0; attempt < credentialReportGenerateAttempts; attempt++ {
		generated, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, false, err
		}
		if generated == nil || credentialReportReady(generated.State) {
			out, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			if err == nil {
				return out, true, nil
			}
			if !credentialReportPending(err) {
				return nil, false, err
			}
		}
		if attempt == credentialReportGenerateAttempts-1 {
			break
		}
		if err := waitForCredentialReport(ctx); err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

func credentialReportReady(state iamtypes.ReportStateType) bool {
	return state == "" || state == iamtypes.ReportStateTypeComplete
}

func credentialReportPending(err error) bool {
	var expired *iamtypes.CredentialReportExpiredException
	if errors.As(err, &expired) {
		return true
	}
	var missing *iamtypes.CredentialReportNotPresentException
	if errors.As(err, &missing) {
		return true
	}
	var notReady *iamtypes.CredentialReportNotReadyException
	return errors.As(err, &notReady)
}

func waitForCredentialReport(ctx context.Context) error {
	timer := time.NewTimer(credentialReportGenerateDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

func parseCredentialReport(content []byte) ([]map[string]string, error) {
	rows, err := parseCredentialReportCSV(string(content))
	if err == nil && len(rows) > 0 {
		return rows, nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
	if decodeErr != nil {
		return rows, err
	}
	decodedRows, decodedErr := parseCredentialReportCSV(string(decoded))
	if decodedErr != nil {
		return rows, err
	}
	return decodedRows, nil
}

func parseCredentialReportCSV(content string) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}
	headers := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, record := range records[1:] {
		row := make(map[string]string, len(headers))
		for index, header := range headers {
			if index >= len(record) {
				row[header] = ""
				continue
			}
			row[header] = record[index]
		}
		if firstNonEmpty(row["user"], row["arn"]) != "" {
			rows = append(rows, row)
		}
	}
	return rows, nil
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
			builder.WriteByte(byte(char + ('a' - 'A')))
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
