package remediation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/testutil"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestExecutor_ApproveBypassesApprovalGate(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "approval-test",
		Name:    "Approval Test",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type:             ActionNotifySlack,
				RequiresApproval: true,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{Type: TriggerManual})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}

	if err := executor.Approve(context.Background(), execution.ID, "alice"); err != nil {
		// notify_slack fails when notifications are not configured in this test setup.
		t.Logf("Approve returned expected execution error: %v", err)
	}
	if execution.Status == ExecutionApproval {
		t.Fatalf("status remained %s after approve", ExecutionApproval)
	}
	if approvedBy, _ := execution.TriggerData["approved_by"].(string); approvedBy != "alice" {
		t.Fatalf("approved_by = %q, want alice", approvedBy)
	}
}

func TestExecutor_RemoteActionFailsWithoutRemoteCaller(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "remote-action-test",
		Name:    "Remote Action Test",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type: ActionUpdateCRMField,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{Type: TriggerManual})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected execute to fail without remote caller")
	}
	if !strings.Contains(err.Error(), "remote tool caller not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
}

func TestExecutor_SendCustomerCommRequiresApprovalByDefault(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "send-customer-comm",
		Name:    "Send Customer Communication",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerManual,
		},
		Actions: []Action{
			{
				Type: ActionSendCustomerComm,
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type: TriggerManual,
		Data: map[string]any{
			"finding_id": "finding-2",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected execution")
	}
	execution := executions[0]

	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"slack.send_message": {{output: `{"ok":true}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}
	if len(caller.calls) != 0 {
		t.Fatalf("expected no remote calls before approval, got %v", caller.calls)
	}

	if err := executor.Approve(context.Background(), execution.ID, "manager@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(caller.calls) == 0 {
		t.Fatal("expected remote call after approval")
	}
}

func TestExecutor_RestrictPublicStorageAccessDryRunCapturesMetadata(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-storage-dry-run",
		Name:    "Restrict Public Storage Dry Run",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicStorageAccess,
			Config: map[string]string{
				"dry_run":       "true",
				"approval_mode": "auto",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-no-public-access",
		EntityID: "bucket:public-assets",
		Data: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_name":     "public-assets",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource": map[string]any{
				"public_access": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(execution.Actions) != 1 {
		t.Fatalf("expected one action result, got %d", len(execution.Actions))
	}
	metadata := execution.Actions[0].Metadata
	if dryRun, _ := metadata["dry_run"].(bool); !dryRun {
		t.Fatalf("expected dry_run metadata, got %#v", metadata)
	}
	if requiresApproval, _ := metadata["requires_approval"].(bool); requiresApproval {
		t.Fatalf("expected dry-run action with approval_mode=auto to report requires_approval=false, got %#v", metadata)
	}
	if metadata["planned_tool"] != "aws.s3.block_public_access" {
		t.Fatalf("unexpected planned tool metadata: %#v", metadata["planned_tool"])
	}
	after, _ := metadata["after"].(map[string]any)
	if planned, _ := after["planned"].(bool); !planned {
		t.Fatalf("expected planned after-state metadata, got %#v", after)
	}
}

func TestExecutor_RestrictPublicStorageAccessRequiresApprovalByDefault(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-storage",
		Name:    "Restrict Public Storage",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicStorageAccess,
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-no-public-access",
		EntityID: "bucket:public-assets",
		Data: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_name":     "public-assets",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource": map[string]any{
				"public_access": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"aws.s3.block_public_access": {{output: `{"changed":true}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}
	if len(caller.calls) != 0 {
		t.Fatalf("expected no remote call before approval, got %v", caller.calls)
	}

	if err := executor.Approve(context.Background(), execution.ID, "security@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(caller.calls) != 1 || caller.calls[0] != "aws.s3.block_public_access" {
		t.Fatalf("unexpected remote calls: %v", caller.calls)
	}
}

func TestExecutor_RestrictPublicStorageAccessDoesNotTrustStalePolicyWithoutCurrentPublicSignal(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-storage-stale-policy",
		Name:    "Restrict Public Storage Stale Policy",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicStorageAccess,
			Config: map[string]string{
				"dry_run":       "true",
				"approval_mode": "auto",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-no-public-access",
		EntityID: "bucket:public-assets",
		Data: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_name":     "public-assets",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource_json": map[string]any{
				"public_access": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected precondition failure")
	}
	if !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
	if len(execution.Actions) != 1 || execution.Actions[0].Metadata == nil {
		t.Fatalf("expected failed action metadata, got %#v", execution.Actions)
	}
	preconditions, _ := execution.Actions[0].Metadata["preconditions"].([]map[string]any)
	if len(preconditions) == 0 {
		t.Fatalf("expected preconditions metadata, got %#v", execution.Actions[0].Metadata)
	}
}

func TestExecutor_EnableBucketDefaultEncryptionTerraformModeCapturesArtifact(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "enable-bucket-default-encryption-terraform",
		Name:    "Enable Bucket Default Encryption Terraform",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionEnableBucketDefaultEncryption,
			Config: map[string]string{
				"delivery_mode": "terraform",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-encryption-enabled",
		EntityID: "bucket:audit-logs",
		Data: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_name":     "audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"iac_file":          "infra/storage/main.tf",
			"iac_module":        "storage",
			"resource": map[string]any{
				"default_encryption_enabled": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(execution.Actions) != 1 {
		t.Fatalf("expected one action result, got %d", len(execution.Actions))
	}
	metadata := execution.Actions[0].Metadata
	if metadata["delivery_mode"] != "terraform" {
		t.Fatalf("expected terraform delivery mode, got %#v", metadata["delivery_mode"])
	}
	if requiresApproval, _ := metadata["requires_approval"].(bool); requiresApproval {
		t.Fatalf("expected terraform generation not to require approval by default, got %#v", metadata)
	}
	if plannedTool := stringValue(metadata["planned_tool"]); plannedTool != "" {
		t.Fatalf("expected no planned tool for terraform delivery, got %#v", metadata["planned_tool"])
	}
	if metadata["sse_algorithm"] != "AES256" {
		t.Fatalf("unexpected sse_algorithm metadata: %#v", metadata["sse_algorithm"])
	}
	artifact, _ := metadata["artifact"].(map[string]any)
	if artifact["path"] != "infra/storage/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected terraform artifact path: %#v", artifact["path"])
	}
	if artifact["resource_address"] != "aws_s3_bucket_server_side_encryption_configuration.audit_logs_default_encryption" {
		t.Fatalf("unexpected terraform resource address: %#v", artifact["resource_address"])
	}
	content, _ := artifact["content"].(string)
	if !strings.Contains(content, `resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs_default_encryption"`) {
		t.Fatalf("expected terraform resource block, got %q", content)
	}
	after, _ := metadata["after"].(map[string]any)
	if planned, _ := after["planned"].(bool); !planned {
		t.Fatalf("expected planned after-state metadata, got %#v", after)
	}
}

func TestExecutor_EnableBucketDefaultEncryptionUsesCatalogDefaultTerraformMode(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "enable-bucket-default-encryption-catalog-default",
		Name:    "Enable Bucket Default Encryption Catalog Default",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionEnableBucketDefaultEncryption,
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-encryption-enabled",
		EntityID: "bucket:audit-logs",
		Data: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_name":     "audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.module.storage.aws_s3_bucket.audit_logs",
			"resource": map[string]any{
				"default_encryption_enabled": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	metadata := execution.Actions[0].Metadata
	if metadata["delivery_mode"] != "terraform" {
		t.Fatalf("expected catalog default terraform delivery mode, got %#v", metadata["delivery_mode"])
	}
	if requiresApproval, _ := metadata["requires_approval"].(bool); requiresApproval {
		t.Fatalf("expected catalog default terraform delivery not to require approval, got %#v", metadata)
	}
	artifact, _ := metadata["artifact"].(map[string]any)
	if artifact["path"] != "generated/terraform/platform/storage/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected terraform artifact path: %#v", artifact["path"])
	}
}

func TestExecutor_NonCatalogTerraformDeliveryDoesNotBypassApproval(t *testing.T) {
	executor := NewExecutor(NewEngine(testutil.Logger()), nil, nil, nil, nil)
	if !executor.actionRequiresApproval(Action{
		Type: ActionPauseSubscription,
		Config: map[string]string{
			"delivery_mode": "terraform",
		},
	}) {
		t.Fatal("expected non-catalog action to keep approval requirement")
	}
}

func TestExecutor_EnableBucketDefaultEncryptionRemoteApplyRequiresApprovalByDefault(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "enable-bucket-default-encryption",
		Name:    "Enable Bucket Default Encryption",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionEnableBucketDefaultEncryption,
			Config: map[string]string{
				"delivery_mode": "remote_apply",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-encryption-enabled",
		EntityID: "arn:aws:s3:::audit-logs",
		Data: map[string]any{
			"resource_id":       "arn:aws:s3:::audit-logs",
			"resource_name":     "audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource": map[string]any{
				"default_encryption_enabled": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"aws.s3.put_bucket_encryption": {{output: `{"changed":true}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}
	if len(caller.calls) != 0 {
		t.Fatalf("expected no remote call before approval, got %v", caller.calls)
	}

	if err := executor.Approve(context.Background(), execution.ID, "security@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(caller.calls) != 1 || caller.calls[0] != "aws.s3.put_bucket_encryption" {
		t.Fatalf("unexpected remote calls: %v", caller.calls)
	}
	var payload map[string]any
	if err := json.Unmarshal(caller.payloads[0], &payload); err != nil {
		t.Fatalf("unmarshal remote payload: %v", err)
	}
	triggerData, _ := payload["trigger_data"].(map[string]any)
	if triggerData["sse_algorithm"] != "AES256" {
		t.Fatalf("expected default sse_algorithm in trigger data, got %#v", triggerData["sse_algorithm"])
	}
}

func TestExecutor_EnableBucketDefaultEncryptionTerraformModeHonorsExplicitApprovalOverride(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "enable-bucket-default-encryption-terraform-approval",
		Name:    "Enable Bucket Default Encryption Terraform Approval",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionEnableBucketDefaultEncryption,
			Config: map[string]string{
				"delivery_mode": "terraform",
				"approval_mode": "required",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-encryption-enabled",
		EntityID: "arn:aws:s3:::audit-logs",
		Data: map[string]any{
			"resource_id":       "arn:aws:s3:::audit-logs",
			"resource_name":     "audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"iac_file":          "infra/storage/main.tf",
			"resource": map[string]any{
				"default_encryption_enabled": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}

	if err := executor.Approve(context.Background(), execution.ID, "security@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	artifact, _ := execution.Actions[0].Metadata["artifact"].(map[string]any)
	if artifact["path"] != "infra/storage/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected terraform artifact path after approval: %#v", artifact["path"])
	}
}

func TestExecutor_EnableBucketDefaultEncryptionDoesNotTrustStalePolicyWhenResourceJSONShowsEncrypted(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "enable-bucket-default-encryption-stale-policy",
		Name:    "Enable Bucket Default Encryption Stale Policy",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionEnableBucketDefaultEncryption,
			Config: map[string]string{
				"delivery_mode": "terraform",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-encryption-enabled",
		EntityID: "bucket:audit-logs",
		Data: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_name":     "audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource": map[string]any{
				"resource_json": map[string]any{
					"encryption_configuration": map[string]any{
						"rules": []any{
							map[string]any{"sse_algorithm": "AES256"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected precondition failure")
	}
	if !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
	if len(execution.Actions) != 1 || execution.Actions[0].Metadata == nil {
		t.Fatalf("expected failed action metadata, got %#v", execution.Actions)
	}
	preconditions, _ := execution.Actions[0].Metadata["preconditions"].([]map[string]any)
	if len(preconditions) == 0 {
		t.Fatalf("expected preconditions metadata, got %#v", execution.Actions[0].Metadata)
	}
}

func TestExecutor_RestrictPublicSecurityGroupIngressDryRunCapturesMetadata(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-security-group-ingress-dry-run",
		Name:    "Restrict Public Security Group Ingress Dry Run",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicSecurityGroupIngress,
			Config: map[string]string{
				"dry_run":       "true",
				"approval_mode": "auto",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-security-group-restrict-ssh",
		EntityID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
		Data: map[string]any{
			"resource_id":       "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
			"resource_name":     "public-ssh",
			"resource_type":     "security_group",
			"resource_platform": "aws",
			"resource": map[string]any{
				"ip_permissions": []any{
					map[string]any{
						"IpProtocol": "tcp",
						"FromPort":   22,
						"ToPort":     22,
						"IpRanges": []any{
							map[string]any{"CidrIp": "0.0.0.0/0"},
						},
					},
					map[string]any{
						"IpProtocol": "tcp",
						"FromPort":   443,
						"ToPort":     443,
						"IpRanges": []any{
							map[string]any{"CidrIp": "0.0.0.0/0"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(execution.Actions) != 1 {
		t.Fatalf("expected one action result, got %d", len(execution.Actions))
	}
	metadata := execution.Actions[0].Metadata
	if dryRun, _ := metadata["dry_run"].(bool); !dryRun {
		t.Fatalf("expected dry_run metadata, got %#v", metadata)
	}
	if metadata["planned_tool"] != "aws.ec2.revoke_security_group_ingress" {
		t.Fatalf("unexpected planned tool metadata: %#v", metadata["planned_tool"])
	}
	if matchedRuleCount, _ := metadata["matched_rule_count"].(int); matchedRuleCount != 1 {
		t.Fatalf("matched_rule_count = %#v, want 1", metadata["matched_rule_count"])
	}
	matchedPorts, _ := metadata["matched_ports"].([]string)
	if len(matchedPorts) != 1 || matchedPorts[0] != "22" {
		t.Fatalf("matched_ports = %#v, want [22]", metadata["matched_ports"])
	}
	matchedCIDRs, _ := metadata["matched_cidrs"].([]string)
	if len(matchedCIDRs) != 1 || matchedCIDRs[0] != "0.0.0.0/0" {
		t.Fatalf("matched_cidrs = %#v, want [0.0.0.0/0]", metadata["matched_cidrs"])
	}
	after, _ := metadata["after"].(map[string]any)
	if planned, _ := after["planned"].(bool); !planned {
		t.Fatalf("expected planned after-state metadata, got %#v", after)
	}
}

func TestExecutor_RestrictPublicSecurityGroupIngressRequiresApprovalByDefault(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-security-group-ingress",
		Name:    "Restrict Public Security Group Ingress",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicSecurityGroupIngress,
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-security-group-restrict-rdp",
		EntityID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-456",
		Data: map[string]any{
			"resource_id":       "arn:aws:ec2:us-east-1:123456789012:security-group/sg-456",
			"resource_name":     "public-rdp",
			"resource_type":     "security_group_rule",
			"resource_platform": "aws",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         3389,
			"to_port":           3389,
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"aws.ec2.revoke_security_group_ingress": {{output: `{"revoked":1}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}
	if len(caller.calls) != 0 {
		t.Fatalf("expected no remote call before approval, got %v", caller.calls)
	}

	if err := executor.Approve(context.Background(), execution.ID, "security@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if len(caller.calls) != 1 || caller.calls[0] != "aws.ec2.revoke_security_group_ingress" {
		t.Fatalf("unexpected remote calls: %v", caller.calls)
	}
	var payload map[string]any
	if err := json.Unmarshal(caller.payloads[0], &payload); err != nil {
		t.Fatalf("unmarshal remote payload: %v", err)
	}
	triggerData, _ := payload["trigger_data"].(map[string]any)
	if _, ok := triggerData["security_group_rule_matches"].([]any); !ok {
		t.Fatalf("expected security_group_rule_matches in trigger data payload, got %#v", triggerData["security_group_rule_matches"])
	}
}

func TestExecutor_RestrictPublicSecurityGroupIngressFailsPreconditionWhenPolicyDoesNotMatchRule(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "restrict-public-security-group-ingress-no-match",
		Name:    "Restrict Public Security Group Ingress No Match",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicSecurityGroupIngress,
			Config: map[string]string{
				"dry_run":       "true",
				"approval_mode": "auto",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-security-group-restrict-ssh",
		EntityID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-789",
		Data: map[string]any{
			"resource_id":       "arn:aws:ec2:us-east-1:123456789012:security-group/sg-789",
			"resource_name":     "public-web",
			"resource_type":     "security_group",
			"resource_platform": "aws",
			"resource": map[string]any{
				"ip_permissions": []any{
					map[string]any{
						"IpProtocol": "tcp",
						"FromPort":   443,
						"ToPort":     443,
						"IpRanges": []any{
							map[string]any{"CidrIp": "0.0.0.0/0"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected precondition failure")
	}
	if !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
}

func TestExecutor_DisableStaleAccessKeyFailsPreconditionWhenKeyIsFresh(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "disable-fresh-access-key",
		Name:    "Disable Fresh Access Key",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionDisableStaleAccessKey,
			Config: map[string]string{
				"approval_mode": "auto",
				"inactive_days": "90",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-iam-user-unused-credentials",
		EntityID: "iam_user:alice",
		Data: map[string]any{
			"resource_id":       "iam_user:alice",
			"resource_name":     "alice",
			"resource_type":     "identity/user",
			"resource_platform": "aws",
			"resource": map[string]any{
				"access_key_metadata": []any{
					map[string]any{"id": "AKIAFRESH", "last_used_days": 14},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, nil)

	err = executor.Execute(context.Background(), execution)
	if err == nil {
		t.Fatal("expected precondition failure")
	}
	if !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if execution.Status != ExecutionFailed {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionFailed)
	}
	if len(execution.Actions) != 1 || execution.Actions[0].Metadata == nil {
		t.Fatalf("expected metadata on failed action, got %#v", execution.Actions)
	}
}

func TestExecutor_DisableStaleAccessKeyUsesRemoteToolAfterApproval(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "disable-stale-access-key",
		Name:    "Disable Stale Access Key",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionDisableStaleAccessKey,
			Config: map[string]string{
				"inactive_days": "90",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-iam-user-unused-credentials",
		EntityID: "iam_user:alice",
		Data: map[string]any{
			"resource_id":       "iam_user:alice",
			"resource_name":     "alice",
			"resource_type":     "identity/user",
			"resource_platform": "aws",
			"resource": map[string]any{
				"access_key_metadata": []any{
					map[string]any{"id": "AKIASTALE", "last_used_days": 121},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"aws.iam.disable_access_key": {{output: `{"disabled":true}`}},
		},
	}
	executor := NewExecutor(engine, nil, nil, nil, nil)
	executor.SetRemoteCaller(caller)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execution.Status != ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionApproval)
	}

	if err := executor.Approve(context.Background(), execution.ID, "manager@example.com"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if execution.Status != ExecutionCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, ExecutionCompleted)
	}
	if execution.TriggerData["access_key_id"] != "AKIASTALE" {
		t.Fatalf("expected selected access_key_id to be persisted, got %#v", execution.TriggerData["access_key_id"])
	}
	if len(caller.calls) != 1 || caller.calls[0] != "aws.iam.disable_access_key" {
		t.Fatalf("unexpected remote calls: %v", caller.calls)
	}
	if len(caller.payloads) != 1 {
		t.Fatalf("expected one remote payload, got %d", len(caller.payloads))
	}
	var payload map[string]any
	if err := json.Unmarshal(caller.payloads[0], &payload); err != nil {
		t.Fatalf("unmarshal remote payload: %v", err)
	}
	if payload["provider"] != "aws" {
		t.Fatalf("unexpected provider payload: %#v", payload["provider"])
	}
	triggerData, _ := payload["trigger_data"].(map[string]any)
	if triggerData["access_key_id"] != "AKIASTALE" {
		t.Fatalf("expected access_key_id in trigger data payload, got %#v", triggerData["access_key_id"])
	}
}

func TestExecutor_ApprovalWebhookIncludesCatalogActions(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rule := Rule{
		ID:      "catalog-approval-webhook",
		Name:    "Catalog approval webhook",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{
			Type: ActionRestrictPublicStorageAccess,
			Config: map[string]string{
				"approval_mode": "required",
			},
		}},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	hooks := webhooks.NewServiceForTesting()
	var approvalEvent webhooks.Event
	hooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		if event.Type == webhooks.EventApprovalRequested {
			approvalEvent = event
		}
		return nil
	})

	executions, err := engine.Evaluate(context.Background(), Event{
		Type:     TriggerManual,
		PolicyID: "aws-s3-bucket-no-public-access",
		EntityID: "bucket:public-assets",
		Data: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_name":     "public-assets",
			"resource_type":     "bucket",
			"resource_platform": "aws",
			"resource": map[string]any{
				"public_access": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	execution := executions[0]
	executor := NewExecutor(engine, nil, nil, nil, hooks)

	if err := executor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if approvalEvent.Type != webhooks.EventApprovalRequested {
		t.Fatalf("expected approval webhook event, got %#v", approvalEvent)
	}
	actions, ok := approvalEvent.Data["approval_actions"].([]string)
	if !ok || len(actions) != 1 || actions[0] != string(ActionRestrictPublicStorageAccess) {
		t.Fatalf("expected catalog action in approval webhook, got %#v", approvalEvent.Data["approval_actions"])
	}
}

func TestRemediationExecutionToSharedPreservesResourceIDFallback(t *testing.T) {
	execution := &Execution{
		ID:       "exec-1",
		RuleID:   "rule-1",
		RuleName: "Rule",
		Status:   ExecutionPending,
		TriggerData: map[string]any{
			"resource_id":   "bucket:public-assets",
			"resource_type": "bucket",
		},
	}

	shared := remediationExecutionToShared(execution)
	if shared.ResourceID != "bucket:public-assets" {
		t.Fatalf("resource id = %q, want bucket:public-assets", shared.ResourceID)
	}
}

func TestCaptureAccessKeyEvidencePrefersSelectedCandidateID(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"resource_id":   "iam_user:alice",
			"resource_type": "identity/user",
			"access_key_id": "AKIAFRESH",
		},
	}

	evidence := captureAccessKeyEvidence(execution, accessKeyCandidate{
		ID:           "AKIASTALE",
		InactiveDays: 121,
		Source:       "access_key_metadata",
	}, 90)

	if got := evidence["access_key_id"]; got != "AKIASTALE" {
		t.Fatalf("access_key_id = %#v, want AKIASTALE", got)
	}
}
