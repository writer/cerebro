package graph

import (
	"testing"
)

func TestParseAWSPolicy(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:PutObject"],
				"Resource": "arn:aws:s3:::my-bucket/*"
			},
			{
				"Effect": "Deny",
				"Action": "s3:DeleteObject",
				"Resource": "*"
			}
		]
	}`

	stmts, err := ParseAWSPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stmts) != 2 {
		t.Errorf("expected 2 statements, got %d", len(stmts))
	}

	// Check first statement
	if stmts[0].Effect != "Allow" {
		t.Errorf("expected Allow effect, got %s", stmts[0].Effect)
	}
	if len(stmts[0].Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(stmts[0].Actions))
	}
	if stmts[0].Resources[0] != "arn:aws:s3:::my-bucket/*" {
		t.Errorf("expected resource arn:aws:s3:::my-bucket/*, got %s", stmts[0].Resources[0])
	}

	// Check second statement
	if stmts[1].Effect != "Deny" {
		t.Errorf("expected Deny effect, got %s", stmts[1].Effect)
	}
}

func TestParseAWSPolicy_SingleValues(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:*",
				"Resource": "*"
			}
		]
	}`

	stmts, err := ParseAWSPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stmts) != 1 {
		t.Errorf("expected 1 statement, got %d", len(stmts))
	}

	if len(stmts[0].Actions) != 1 || stmts[0].Actions[0] != "s3:*" {
		t.Errorf("expected action s3:*, got %v", stmts[0].Actions)
	}
}

func TestParseAWSPolicy_EmptyDocument(t *testing.T) {
	stmts, err := ParseAWSPolicy("")
	if err != nil {
		t.Errorf("expected no error for empty document, got %v", err)
	}
	if stmts != nil {
		t.Errorf("expected nil for empty document, got %v", stmts)
	}
}

func TestParseTrustPolicy(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	principals, err := ParseTrustPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(principals) != 1 {
		t.Errorf("expected 1 principal, got %d", len(principals))
	}

	if principals[0].ARN != "arn:aws:iam::123456789012:root" {
		t.Errorf("expected ARN arn:aws:iam::123456789012:root, got %s", principals[0].ARN)
	}
	if principals[0].Type != "AWS" {
		t.Errorf("expected type AWS, got %s", principals[0].Type)
	}
}

func TestParseTrustPolicy_ServicePrincipal(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"Service": "ec2.amazonaws.com"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	principals, err := ParseTrustPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(principals) != 1 {
		t.Errorf("expected 1 principal, got %d", len(principals))
	}

	if principals[0].ARN != "service:ec2.amazonaws.com" {
		t.Errorf("expected ARN service:ec2.amazonaws.com, got %s", principals[0].ARN)
	}
	if principals[0].Type != "Service" {
		t.Errorf("expected type Service, got %s", principals[0].Type)
	}
}

func TestParseTrustPolicy_PublicWildcard(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRole"
			}
		]
	}`

	principals, err := ParseTrustPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(principals) != 1 {
		t.Errorf("expected 1 principal, got %d", len(principals))
	}

	if !principals[0].IsPublic {
		t.Error("expected principal to be public")
	}
}

func TestParseTrustPolicy_AWSWildcard(t *testing.T) {
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "*"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	principals, err := ParseTrustPolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(principals) != 1 {
		t.Errorf("expected 1 principal, got %d", len(principals))
	}

	if !principals[0].IsPublic {
		t.Error("expected principal to be public")
	}
}

func TestActionsToEdgeKind(t *testing.T) {
	tests := []struct {
		actions  []string
		expected EdgeKind
	}{
		{[]string{"s3:GetObject"}, EdgeKindCanRead},
		{[]string{"s3:PutObject", "s3:GetObject"}, EdgeKindCanWrite},
		{[]string{"s3:DeleteObject"}, EdgeKindCanDelete},
		{[]string{"s3:*"}, EdgeKindCanAdmin},
		{[]string{"*"}, EdgeKindCanAdmin},
		{[]string{"iam:*"}, EdgeKindCanAdmin},
	}

	for _, tt := range tests {
		t.Run(tt.actions[0], func(t *testing.T) {
			got := ActionsToEdgeKind(tt.actions)
			if got != tt.expected {
				t.Errorf("got %s, want %s", got, tt.expected)
			}
		})
	}
}
