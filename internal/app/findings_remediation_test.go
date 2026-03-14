package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/ticketing"
	"github.com/evalops/cerebro/internal/webhooks"
)

func TestUpsertFindingAndRemediate_TriggersResolveRuleOnCreate(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	findingStore := findings.NewStore()
	remediationEngine := remediation.NewEngine(logger)
	app := &App{
		Logger:        logger,
		Findings:      findingStore,
		Remediation:   remediationEngine,
		Notifications: notifications.NewManager(),
		Ticketing:     ticketing.NewService(),
		Webhooks:      webhooks.NewServiceForTesting(),
	}
	app.RemediationExecutor = remediation.NewExecutor(app.Remediation, app.Ticketing, app.Notifications, app.Findings, app.Webhooks)

	err := app.Remediation.AddRule(remediation.Rule{
		ID:          "test-resolve-created-finding",
		Name:        "Resolve created finding",
		Description: "test",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: "identity-stale-inactive-user",
		},
		Actions: []remediation.Action{
			{Type: remediation.ActionResolveFinding},
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	stored := app.upsertFindingAndRemediate(context.Background(), policy.Finding{
		ID:           "finding-1",
		PolicyID:     "identity-stale-inactive-user",
		PolicyName:   "Inactive Identity Account",
		Severity:     "low",
		ResourceID:   "user:alice",
		ResourceType: "identity/user",
		Resource: map[string]interface{}{
			"user": "alice",
		},
		Description: "stale account",
		Remediation: "disable account",
	})
	if stored == nil {
		t.Fatal("expected finding to be stored")
	}
	if strings.ToUpper(stored.Status) != "RESOLVED" {
		t.Fatalf("expected finding to be resolved by remediation, got %s", stored.Status)
	}

	executions := app.Remediation.ListExecutions(20)
	foundRuleExecution := false
	for _, execution := range executions {
		if execution.RuleID == "test-resolve-created-finding" {
			foundRuleExecution = true
			break
		}
	}
	if !foundRuleExecution {
		t.Fatal("expected remediation execution for test-resolve-created-finding")
	}
}

func TestUpsertFindingAndRemediate_SkipsCreatedTriggerOnReobservation(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	findingStore := findings.NewStore()
	remediationEngine := remediation.NewEngine(logger)
	app := &App{
		Logger:        logger,
		Findings:      findingStore,
		Remediation:   remediationEngine,
		Notifications: notifications.NewManager(),
		Ticketing:     ticketing.NewService(),
		Webhooks:      webhooks.NewServiceForTesting(),
	}
	app.RemediationExecutor = remediation.NewExecutor(app.Remediation, app.Ticketing, app.Notifications, app.Findings, app.Webhooks)

	err := app.Remediation.AddRule(remediation.Rule{
		ID:          "test-created-trigger-once",
		Name:        "Created trigger once",
		Description: "test",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: "identity-stale-inactive-user",
		},
		Actions: []remediation.Action{
			{Type: remediation.ActionResolveFinding},
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	pf := policy.Finding{
		ID:           "finding-2",
		PolicyID:     "identity-stale-inactive-user",
		PolicyName:   "Inactive Identity Account",
		Severity:     "low",
		ResourceID:   "user:bob",
		ResourceType: "identity/user",
		Resource: map[string]interface{}{
			"user": "bob",
		},
		Description: "stale account",
		Remediation: "disable account",
	}

	app.upsertFindingAndRemediate(context.Background(), pf)
	firstCount := 0
	for _, execution := range app.Remediation.ListExecutions(50) {
		if execution.RuleID == "test-created-trigger-once" {
			firstCount++
		}
	}
	if firstCount == 0 {
		t.Fatal("expected first remediation execution")
	}

	app.upsertFindingAndRemediate(context.Background(), pf)
	secondCount := 0
	for _, execution := range app.Remediation.ListExecutions(50) {
		if execution.RuleID == "test-created-trigger-once" {
			secondCount++
		}
	}
	if secondCount != firstCount {
		t.Fatalf("expected no additional created-trigger execution on re-observation: first=%d second=%d", firstCount, secondCount)
	}
}

func TestUpsertFindingAndRemediate_ForwardsRichResourceContext(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	findingStore := findings.NewStore()
	remediationEngine := remediation.NewEngine(logger)
	app := &App{
		Logger:        logger,
		Findings:      findingStore,
		Remediation:   remediationEngine,
		Notifications: notifications.NewManager(),
		Ticketing:     ticketing.NewService(),
		Webhooks:      webhooks.NewServiceForTesting(),
	}
	app.RemediationExecutor = remediation.NewExecutor(app.Remediation, app.Ticketing, app.Notifications, app.Findings, app.Webhooks)

	err := app.Remediation.AddRule(remediation.Rule{
		ID:          "test-rich-context-forwarding",
		Name:        "Rich context forwarding",
		Description: "test",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: "aws-s3-bucket-no-public-access",
		},
		Actions: []remediation.Action{
			{
				Type: remediation.ActionRestrictPublicStorageAccess,
				Config: map[string]string{
					"dry_run":       "true",
					"approval_mode": "auto",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	stored := app.upsertFindingAndRemediate(context.Background(), policy.Finding{
		ID:           "finding-rich-1",
		PolicyID:     "aws-s3-bucket-no-public-access",
		PolicyName:   "Public S3 bucket",
		Severity:     "high",
		ResourceID:   "bucket:public-assets",
		ResourceName: "public-assets",
		ResourceType: "bucket",
		Title:        "Public assets bucket",
		RiskCategories: []string{
			"public_access",
		},
		Resource: map[string]interface{}{
			"public_access": true,
			"arn":           "arn:aws:s3:::public-assets",
			"region":        "us-east-1",
			"account_id":    "123456789012",
			"tags": map[string]interface{}{
				"owner": "security",
			},
			"resource_json": map[string]interface{}{
				"public_access": true,
				"versioning":    false,
			},
		},
		Description: "bucket is public",
		Remediation: "remove public access",
	})
	if stored == nil {
		t.Fatal("expected finding to be stored")
	}

	var execution *remediation.Execution
	for _, candidate := range app.Remediation.ListExecutions(20) {
		if candidate.RuleID == "test-rich-context-forwarding" {
			execution = candidate
			break
		}
	}
	if execution == nil {
		t.Fatal("expected remediation execution for rich-context rule")
	}
	if execution.TriggerData["resource_name"] != "public-assets" {
		t.Fatalf("expected resource_name in trigger data, got %#v", execution.TriggerData["resource_name"])
	}
	if execution.TriggerData["resource_platform"] != "aws" {
		t.Fatalf("expected resource_platform in trigger data, got %#v", execution.TriggerData["resource_platform"])
	}
	if execution.TriggerData["resource_external_id"] != "arn:aws:s3:::public-assets" {
		t.Fatalf("expected resource_external_id in trigger data, got %#v", execution.TriggerData["resource_external_id"])
	}
	if _, ok := execution.TriggerData["resource"].(map[string]interface{}); !ok {
		t.Fatalf("expected resource payload in trigger data, got %#v", execution.TriggerData["resource"])
	}
	if categories, ok := execution.TriggerData["risk_categories"].([]string); !ok || len(categories) != 1 || categories[0] != "public_access" {
		t.Fatalf("expected risk_categories in trigger data, got %#v", execution.TriggerData["risk_categories"])
	}
}
