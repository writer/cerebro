package sync

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func (s *AWSSyncer) syncIAMRoles(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := iam.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_iam_roles", []string{
		"arn", "account_id", "role_name", "role_id", "path", "name",
		"assume_role_policy_document", "create_date", "max_session_duration",
		"permissions_boundary", "tags", "description",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
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

	changes, err := s.upsertRows(ctx, "aws_iam_roles", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_iam_roles", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncIAMUsers(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := iam.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	if err := s.ensureTable(ctx, "aws_iam_users", []string{
		"arn", "account_id", "user_name", "name", "user_id", "path", "create_date",
		"password_last_used", "permissions_boundary", "tags",
	}); err != nil {
		return nil, err
	}

	var rows []map[string]interface{}
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
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

	changes, err := s.upsertRows(ctx, "aws_iam_users", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_iam_users", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}

func (s *AWSSyncer) syncCredentialReport(ctx context.Context, cfg aws.Config) (*SyncResult, error) {
	start := time.Now()
	client := iam.NewFromConfig(cfg)
	accountID := s.getAccountID(ctx, cfg)

	expectedCols := []string{
		"user", "arn", "account_id", "user_creation_time",
		"password_enabled", "password_last_used", "password_last_changed",
		"mfa_active", "access_key_1_active", "access_key_1_last_rotated",
		"access_key_2_active", "access_key_2_last_rotated",
	}

	if err := s.ensureTable(ctx, "aws_iam_credential_reports", expectedCols); err != nil {
		return nil, err
	}

	// Generate credential report
	_, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
	if err != nil {
		return nil, fmt.Errorf("generate credential report: %w", err)
	}

	time.Sleep(2 * time.Second)

	reportOut, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, fmt.Errorf("get credential report: %w", err)
	}

	reader := csv.NewReader(strings.NewReader(string(reportOut.Content)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse credential report: %w", err)
	}

	expectedSet := make(map[string]bool)
	for _, col := range expectedCols {
		expectedSet[col] = true
	}

	var rows []map[string]interface{}
	if len(records) > 1 {
		headers := records[0]
		for _, record := range records[1:] {
			row := map[string]interface{}{
				"_cq_id":     record[1],
				"account_id": accountID,
			}
			for i, header := range headers {
				if i < len(record) {
					colName := strings.ToLower(header)
					if expectedSet[colName] {
						row[colName] = record[i]
					}
				}
			}
			rows = append(rows, row)
		}
	}

	changes, err := s.upsertRows(ctx, "aws_iam_credential_reports", rows)
	if err != nil {
		return nil, err
	}

	return &SyncResult{Table: "aws_iam_credential_reports", Synced: len(rows), Duration: time.Since(start), Changes: changes}, nil
}
