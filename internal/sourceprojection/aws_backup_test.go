package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAWSBackupPlanAndRecoveryPointRelationships(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	planARN := "arn:aws:backup:us-east-1:123456789012:backup-plan:plan-123"
	vaultARN := "arn:aws:backup:us-east-1:123456789012:backup-vault:prod-vault"
	recoveryPointARN := "arn:aws:backup:us-east-1:123456789012:recovery-point:rp-123"
	resourceARN := "arn:aws:rds:us-east-1:123456789012:db:orders-db"

	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "backup-plan",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.backup_plan",
		Attributes: map[string]string{
			"backup_plan_arn":           planARN,
			"backup_plan_id":            "plan-123",
			"backup_plan_name":          "prod-plan",
			"domain":                    "123456789012",
			"region":                    "us-east-1",
			"resource_id":               planARN,
			"resource_name":             "prod-plan",
			"resource_provider":         "aws",
			"resource_type":             "backup_plan",
			"target_backup_vault_names": "prod-vault",
		},
	}); err != nil {
		t.Fatalf("Project(backup_plan) error = %v", err)
	}
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "backup-recovery-point",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.backup_recovery_point",
		Attributes: map[string]string{
			"backup_plan_arn":      planARN,
			"backup_plan_id":       "plan-123",
			"backup_rule_id":       "rule-1",
			"backup_vault_arn":     vaultARN,
			"backup_vault_name":    "prod-vault",
			"domain":               "123456789012",
			"recovery_point_arn":   recoveryPointARN,
			"region":               "us-east-1",
			"resource_id":          recoveryPointARN,
			"resource_name":        "orders-db",
			"resource_provider":    "aws",
			"resource_type":        "backup_recovery_point",
			"source_resource_arn":  resourceARN,
			"source_resource_name": "orders-db",
			"source_resource_type": "rds_instance",
		},
	}); err != nil {
		t.Fatalf("Project(backup_recovery_point) error = %v", err)
	}

	planURN := "urn:cerebro:writer:aws_backup_plan:" + planARN
	vaultURN := "urn:cerebro:writer:aws_backup_vault:" + vaultARN
	recoveryURN := "urn:cerebro:writer:aws_backup_recovery_point:" + recoveryPointARN
	sourceURN := "urn:cerebro:writer:aws_rds_instance:" + resourceARN
	if entity := state.entities[vaultURN]; entity == nil || entity.EntityType != "aws.backup.vault" {
		t.Fatalf("backup vault entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, planURN, relationAssociatedWith, vaultURN)
	assertProjectedLink(t, state, recoveryURN, relationBelongsTo, vaultURN)
	assertProjectedLink(t, state, recoveryURN, relationDependsOn, planURN)
	assertProjectedLink(t, state, recoveryURN, relationAssociatedWith, sourceURN)
	assertProjectedLink(t, state, vaultURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
}
