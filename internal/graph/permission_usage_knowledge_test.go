package graph

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestBuildAWSIAMPermissionUsageKnowledgeWritesObservationAndClaim(t *testing.T) {
	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(io.Discard, nil)))

	subjectID := "arn:aws:sso:::permissionSet/ssoins-123/ps-123"
	builder.graph.AddNode(&Node{
		ID:       subjectID,
		Kind:     NodeKindRole,
		Name:     "Admin",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})

	observedAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := observedAt.Add(-180 * 24 * time.Hour)

	source.setResult(awsIAMPermissionUsageKnowledgeQuery, &QueryResult{Rows: []map[string]any{
		{
			"_cq_id":                       "row-aws-1",
			"account_id":                   "123456789012",
			"account_ids":                  []any{"123456789012", "222222222222"},
			"account_count":                2,
			"region":                       "us-east-1",
			"identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-123",
			"permission_set_arn":           "arn:aws:sso:::permissionSet/ssoins-123/ps-123",
			"permission_set_name":          "Admin",
			"sso_role_arns":                []any{"arn:aws:iam::123456789012:role/AWSReservedSSO_Admin_abcdef"},
			"action":                       "iam:CreateUser",
			"usage_status":                 "unused",
			"days_unused":                  200,
			"lookback_days":                180,
			"removal_threshold_days":       180,
			"recommendation":               "Remove iam:CreateUser from the permission set.",
			"evidence_source":              "aws_iam_access_advisor_action_level",
			"confidence":                   "high",
			"coverage":                     "full",
			"scan_window_start":            windowStart,
			"scan_window_end":              observedAt,
			"history_day":                  observedAt.Truncate(24 * time.Hour),
			"assignment_count":             3,
		},
	}})

	builder.buildIAMPermissionUsageKnowledge(context.Background())

	observations := builder.graph.GetNodesByKind(NodeKindObservation)
	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(observations))
	}

	observation := observations[0]
	if observation.Properties["permission"] != "iam:CreateUser" {
		t.Fatalf("unexpected permission in observation: %v", observation.Properties["permission"])
	}
	if observation.Properties["usage_status"] != "unused" {
		t.Fatalf("unexpected usage_status in observation: %v", observation.Properties["usage_status"])
	}

	claims := builder.graph.GetNodesByKind(NodeKindClaim)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}

	claim := claims[0]
	if claim.Properties["subject_id"] != subjectID {
		t.Fatalf("unexpected claim subject: %v", claim.Properties["subject_id"])
	}
	if claim.Properties["predicate"] != iamPermissionUsagePredicate {
		t.Fatalf("unexpected claim predicate: %v", claim.Properties["predicate"])
	}
	if claim.Properties["object_value"] != "unused" {
		t.Fatalf("unexpected claim object value: %v", claim.Properties["object_value"])
	}
}

func TestBuildGCPIAMPermissionUsageKnowledgeCreatesGroupSubject(t *testing.T) {
	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(io.Discard, nil)))

	observedAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := observedAt.Add(-90 * 24 * time.Hour)

	source.setResult(gcpIAMPermissionUsageKnowledgeQuery, &QueryResult{Rows: []map[string]any{
		{
			"_cq_id":                 "row-gcp-1",
			"project_id":             "writer-prod",
			"group_email":            "eng@example.com",
			"permission":             "resourcemanager.projects.get",
			"granted_roles":          []any{"roles/viewer", "roles/logging.privateLogViewer"},
			"usage_status":           "used",
			"days_unused":            2,
			"lookback_days":          90,
			"removal_threshold_days": 180,
			"member_count":           12,
			"members_observed":       8,
			"evidence_source":        "gcp_cloud_audit_logs_authorization_info",
			"confidence":             "medium",
			"coverage":               "partial",
			"scan_window_start":      windowStart,
			"scan_window_end":        observedAt,
			"history_day":            observedAt.Truncate(24 * time.Hour),
			"permission_last_used":   observedAt.Add(-2 * time.Hour),
		},
	}})

	builder.buildIAMPermissionUsageKnowledge(context.Background())

	groupNode, ok := builder.graph.GetNode("group:eng@example.com")
	if !ok {
		t.Fatal("expected group subject node to be created")
	}
	if groupNode.Kind != NodeKindGroup {
		t.Fatalf("expected group node kind, got %s", groupNode.Kind)
	}

	claims := builder.graph.GetNodesByKind(NodeKindClaim)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}
	claim := claims[0]
	if claim.Properties["subject_id"] != "group:eng@example.com" {
		t.Fatalf("unexpected claim subject: %v", claim.Properties["subject_id"])
	}
	if claim.Properties["object_value"] != "used" {
		t.Fatalf("unexpected claim object value: %v", claim.Properties["object_value"])
	}

	observations := builder.graph.GetNodesByKind(NodeKindObservation)
	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(observations))
	}
	roles, ok := observations[0].Properties["granted_roles"].([]string)
	if !ok {
		t.Fatalf("expected granted_roles to be []string, got %T", observations[0].Properties["granted_roles"])
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 granted roles, got %d", len(roles))
	}
}

func TestBuildGCPIAMPermissionUsageKnowledgePreservesAttributionUncertain(t *testing.T) {
	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(io.Discard, nil)))

	observedAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := observedAt.Add(-90 * 24 * time.Hour)

	source.setResult(gcpIAMPermissionUsageKnowledgeQuery, &QueryResult{Rows: []map[string]any{
		{
			"_cq_id":                 "row-gcp-uncertain-1",
			"project_id":             "writer-prod",
			"group_email":            "eng@example.com",
			"permission":             "storage.buckets.get",
			"granted_roles":          []any{"roles/storage.admin"},
			"usage_status":           "attribution_uncertain",
			"days_unused":            14,
			"lookback_days":          90,
			"removal_threshold_days": 180,
			"member_count":           6,
			"members_observed":       2,
			"recommendation":         "Verify attribution before removing the role grant.",
			"evidence_source":        "gcp_cloud_audit_logs_authorization_info",
			"confidence":             "medium",
			"coverage":               "partial",
			"scan_window_start":      windowStart,
			"scan_window_end":        observedAt,
			"history_day":            observedAt.Truncate(24 * time.Hour),
		},
	}})

	builder.buildIAMPermissionUsageKnowledge(context.Background())

	claims := builder.graph.GetNodesByKind(NodeKindClaim)
	if len(claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(claims))
	}
	if claims[0].Properties["object_value"] != "attribution_uncertain" {
		t.Fatalf("expected uncertain claim object value, got %v", claims[0].Properties["object_value"])
	}

	observations := builder.graph.GetNodesByKind(NodeKindObservation)
	if len(observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(observations))
	}
	if observations[0].Properties["usage_status"] != "attribution_uncertain" {
		t.Fatalf("expected uncertain observation status, got %v", observations[0].Properties["usage_status"])
	}
}

func TestBuildCandidateWritesPermissionUsageIntoCandidateOnly(t *testing.T) {
	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(io.Discard, nil)))

	observedAt := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	windowStart := observedAt.Add(-90 * 24 * time.Hour)

	source.setResult(gcpIAMPermissionUsageKnowledgeQuery, &QueryResult{Rows: []map[string]any{{
		"_cq_id":                 "row-gcp-1",
		"project_id":             "writer-prod",
		"group_email":            "eng@example.com",
		"permission":             "resourcemanager.projects.get",
		"granted_roles":          []any{"roles/viewer"},
		"usage_status":           "used",
		"days_unused":            2,
		"lookback_days":          90,
		"removal_threshold_days": 180,
		"member_count":           12,
		"members_observed":       8,
		"evidence_source":        "gcp_cloud_audit_logs_authorization_info",
		"confidence":             "medium",
		"coverage":               "partial",
		"scan_window_start":      windowStart,
		"scan_window_end":        observedAt,
		"history_day":            observedAt.Truncate(24 * time.Hour),
	}}})

	candidate, _, err := builder.BuildCandidate(context.Background())
	if err != nil {
		t.Fatalf("BuildCandidate failed: %v", err)
	}
	if claims := candidate.GetNodesByKind(NodeKindClaim); len(claims) != 1 {
		t.Fatalf("expected candidate to contain 1 permission-usage claim, got %d", len(claims))
	}
	if claims := builder.Graph().GetNodesByKind(NodeKindClaim); len(claims) != 0 {
		t.Fatalf("expected live graph to remain untouched, got %d claims", len(claims))
	}
}
