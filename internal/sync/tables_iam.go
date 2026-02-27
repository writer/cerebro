package sync

import (
	"context"
	"encoding/csv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func (e *SyncEngine) iamRoleTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_roles",
		Columns: []string{"arn", "account_id", "role_name", "role_id", "path", "name", "assume_role_policy_document", "create_date", "max_session_duration", "permissions_boundary", "tags", "description"},
		Fetch:   e.fetchIAMRoles,
	}
}

func (e *SyncEngine) iamUserTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_users",
		Columns: []string{"arn", "account_id", "user_name", "name", "user_id", "path", "create_date", "password_last_used", "permissions_boundary", "tags"},
		Fetch:   e.fetchIAMUsers,
	}
}

func (e *SyncEngine) iamCredentialReportTable() TableSpec {
	return TableSpec{
		Name:    "aws_iam_credential_reports",
		Columns: []string{"user", "arn", "account_id", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed", "mfa_active", "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date", "access_key_1_last_used_days", "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date", "access_key_2_last_used_days", "password_last_used_days"},
		Fetch:   e.fetchCredentialReport,
	}
}

func (e *SyncEngine) fetchIAMRoles(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	// IAM is global, only sync from us-east-1
	if region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			rows = append(rows, map[string]interface{}{
				"_cq_id":                      aws.ToString(role.Arn),
				"arn":                         aws.ToString(role.Arn),
				"account_id":                  accountID,
				"role_name":                   aws.ToString(role.RoleName),
				"name":                        aws.ToString(role.RoleName),
				"role_id":                     aws.ToString(role.RoleId),
				"path":                        aws.ToString(role.Path),
				"assume_role_policy_document": aws.ToString(role.AssumeRolePolicyDocument),
				"create_date":                 role.CreateDate,
				"max_session_duration":        role.MaxSessionDuration,
				"permissions_boundary":        role.PermissionsBoundary,
				"tags":                        role.Tags,
				"description":                 aws.ToString(role.Description),
			})
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchIAMUsers(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	if region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			rows = append(rows, map[string]interface{}{
				"_cq_id":               aws.ToString(user.Arn),
				"arn":                  aws.ToString(user.Arn),
				"account_id":           accountID,
				"user_name":            aws.ToString(user.UserName),
				"name":                 aws.ToString(user.UserName),
				"user_id":              aws.ToString(user.UserId),
				"path":                 aws.ToString(user.Path),
				"create_date":          user.CreateDate,
				"password_last_used":   user.PasswordLastUsed,
				"permissions_boundary": user.PermissionsBoundary,
				"tags":                 user.Tags,
			})
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchCredentialReport(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	if region != "us-east-1" {
		return nil, nil
	}

	client := iam.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	// Generate report
	if _, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, err
	}
	time.Sleep(2 * time.Second)

	reportOut, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(string(reportOut.Content)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	expectedCols := map[string]bool{
		"user": true, "arn": true, "user_creation_time": true,
		"password_enabled": true, "password_last_used": true, "password_last_changed": true,
		"mfa_active": true, "access_key_1_active": true, "access_key_1_last_rotated": true,
		"access_key_1_last_used_date": true,
		"access_key_2_active":         true, "access_key_2_last_rotated": true,
		"access_key_2_last_used_date": true,
	}

	var rows []map[string]interface{}
	if len(records) > 1 {
		headers := records[0]
		now := time.Now().UTC()
		for _, record := range records[1:] {
			row := map[string]interface{}{"account_id": accountID}
			for i, header := range headers {
				if i < len(record) {
					colName := strings.ToLower(header)
					if expectedCols[colName] {
						if parsed, ok := parseCredentialReportValue(colName, record[i]); ok {
							row[colName] = parsed
						}
					}
				}
			}

			if arn := toString(row["arn"]); arn != "" {
				row["_cq_id"] = arn
			} else {
				user := toString(row["user"])
				if user == "" {
					continue
				}
				row["_cq_id"] = user
			}

			addCredentialReportDerivedFields(row, now)
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseCredentialReportValue(column, raw string) (interface{}, bool) {
	value := strings.TrimSpace(raw)
	if value == "" || isCredentialReportNullValue(value) {
		return nil, false
	}

	switch column {
	case "password_enabled", "mfa_active", "access_key_1_active", "access_key_2_active":
		return strings.EqualFold(value, "true"), true
	case "user_creation_time", "password_last_used", "password_last_changed", "access_key_1_last_rotated", "access_key_2_last_rotated", "access_key_1_last_used_date", "access_key_2_last_used_date":
		if ts, ok := parseCredentialReportTime(value); ok {
			return ts, true
		}
	}

	return value, true
}

func addCredentialReportDerivedFields(row map[string]interface{}, now time.Time) {
	if days, ok := credentialReportDaysSince(row["password_last_used"], now); ok {
		row["password_last_used_days"] = days
	}
	if days, ok := credentialReportDaysSince(row["access_key_1_last_used_date"], now); ok {
		row["access_key_1_last_used_days"] = days
	}
	if days, ok := credentialReportDaysSince(row["access_key_2_last_used_date"], now); ok {
		row["access_key_2_last_used_days"] = days
	}
}

func credentialReportDaysSince(value interface{}, now time.Time) (int, bool) {
	ts, ok := parseCredentialReportTimestamp(value)
	if !ok {
		return 0, false
	}
	if ts.After(now) {
		return 0, true
	}
	return int(now.Sub(ts).Hours() / 24), true
}

func parseCredentialReportTimestamp(value interface{}) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), true
	case string:
		return parseCredentialReportTime(typed)
	default:
		return time.Time{}, false
	}
}

func parseCredentialReportTime(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || isCredentialReportNullValue(trimmed) {
		return time.Time{}, false
	}

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05+00:00",
		"2006-01-02T15:04:05-07:00",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, trimmed); err == nil {
			return ts.UTC(), true
		}
	}

	return time.Time{}, false
}

func isCredentialReportNullValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "n/a" || normalized == "no_information" || normalized == "not_supported"
}
