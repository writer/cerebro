package builders

import "testing"

func TestNormalizeTableNames(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple FROM clause",
			input:    "SELECT * FROM aws_iam_users",
			expected: "SELECT * FROM AWS_IAM_USERS",
		},
		{
			name:     "multiline query",
			input:    "SELECT arn, user_name\n\t\tFROM aws_iam_users\n\t\tWHERE account_id = '123'",
			expected: "SELECT arn, user_name\n\t\tFROM AWS_IAM_USERS\n\t\tWHERE account_id = '123'",
		},
		{
			name:     "multiple FROM clauses",
			input:    "SELECT * FROM aws_s3_buckets WHERE id IN (SELECT bucket_id FROM aws_s3_policies)",
			expected: "SELECT * FROM AWS_S3_BUCKETS WHERE id IN (SELECT bucket_id FROM AWS_S3_POLICIES)",
		},
		{
			name:     "join clauses",
			input:    "SELECT * FROM aws_iam_users u JOIN aws_iam_roles r ON u.arn = r.arn",
			expected: "SELECT * FROM AWS_IAM_USERS u JOIN AWS_IAM_ROLES r ON u.arn = r.arn",
		},
		{
			name:     "schema qualified",
			input:    "SELECT * FROM raw.aws_iam_users",
			expected: "SELECT * FROM RAW.AWS_IAM_USERS",
		},
		{
			name:     "case insensitive FROM",
			input:    "SELECT * from aws_iam_roles",
			expected: "SELECT * from AWS_IAM_ROLES",
		},
		{
			name:     "gcp tables",
			input:    "SELECT * FROM gcp_compute_instances",
			expected: "SELECT * FROM GCP_COMPUTE_INSTANCES",
		},
		{
			name:     "no table name",
			input:    "SELECT 1",
			expected: "SELECT 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeTableNames(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTableNames(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
