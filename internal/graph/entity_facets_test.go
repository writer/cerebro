package graph

import (
	"testing"
	"time"
)

func TestGetEntityFacetDefinitionReturnsDeepCopy(t *testing.T) {
	def, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition")
	}
	if len(def.ClaimPredicates) == 0 {
		t.Fatalf("expected cloned definition to retain claim predicates, got %#v", def)
	}
	original := def.ClaimPredicates[0]
	def.ClaimPredicates[0] = "mutated"

	again, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition on second lookup")
	}
	if again.ClaimPredicates[0] != original {
		t.Fatalf("expected registry definition to be isolated from caller mutation, got %#v", again)
	}
}

func TestMaterializeOwnershipFacetUsesManagedByOutgoingEdgesForManagers(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	entity := &Node{ID: "service:payments", Kind: NodeKindService, CreatedAt: now, UpdatedAt: now}
	manager := &Node{ID: "person:alice@example.com", Kind: NodeKindPerson, CreatedAt: now, UpdatedAt: now}
	child := &Node{ID: "service:payments-worker", Kind: NodeKindService, CreatedAt: now, UpdatedAt: now}
	owner := &Node{ID: "group:platform", Kind: NodeKindGroup, CreatedAt: now, UpdatedAt: now}
	g.AddNode(entity)
	g.AddNode(manager)
	g.AddNode(child)
	g.AddNode(owner)
	g.AddEdge(&Edge{
		ID:        "manager-edge",
		Source:    entity.ID,
		Target:    manager.ID,
		Kind:      EdgeKindManagedBy,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})
	g.AddEdge(&Edge{
		ID:        "child-edge",
		Source:    child.ID,
		Target:    entity.ID,
		Kind:      EdgeKindManagedBy,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})
	g.AddEdge(&Edge{
		ID:        "owner-edge",
		Source:    owner.ID,
		Target:    entity.ID,
		Kind:      EdgeKindOwns,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})

	def, ok := GetEntityFacetDefinition("ownership")
	if !ok {
		t.Fatal("expected ownership facet definition")
	}

	record, materialized := materializeOwnershipFacet(g, entity, now, now, def, nil)
	if !materialized {
		t.Fatal("expected ownership facet to materialize")
	}
	owners, _ := record.Fields["owner_ids"].([]string)
	managers, _ := record.Fields["manager_ids"].([]string)
	if len(owners) != 1 || owners[0] != owner.ID {
		t.Fatalf("expected owner list to include %q, got %#v", owner.ID, owners)
	}
	if len(managers) != 1 || managers[0] != manager.ID {
		t.Fatalf("expected manager list to include only %q, got %#v", manager.ID, managers)
	}
}

func TestMaterializeBucketEncryptionFacetUsesBucketPostureAndSubresourceDetails(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	bucket := &Node{
		ID:         "arn:aws:s3:::logs",
		Kind:       NodeKindBucket,
		CreatedAt:  now,
		UpdatedAt:  now,
		Properties: map[string]any{"encrypted": true},
	}
	config := &Node{
		ID:        "bucket_encryption_config:logs",
		Kind:      NodeKindBucketEncryptionConfig,
		CreatedAt: now,
		UpdatedAt: now,
		Properties: map[string]any{
			"encrypted":            false,
			"encryption_algorithm": "aws:kms",
			"encryption_key_id":    "kms:key:logs",
			"bucket_key_enabled":   true,
		},
	}
	g.AddNode(bucket)
	g.AddNode(config)
	g.AddEdge(&Edge{
		ID:        "bucket-encryption-config",
		Source:    config.ID,
		Target:    bucket.ID,
		Kind:      EdgeKindConfigures,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})

	def, ok := GetEntityFacetDefinition("bucket_encryption")
	if !ok {
		t.Fatal("expected bucket_encryption facet definition")
	}

	record, materialized := materializeBucketEncryptionFacet(g, bucket, now, now, def, nil)
	if !materialized {
		t.Fatal("expected bucket encryption facet to materialize")
	}
	if record.Assessment != "pass" {
		t.Fatalf("expected bucket posture to drive pass assessment, got %#v", record)
	}
	if encrypted, _ := record.Fields["encrypted"].(bool); !encrypted {
		t.Fatalf("expected encrypted field to come from bucket posture, got %#v", record.Fields)
	}
	if algorithm, _ := record.Fields["encryption_algorithm"].(string); algorithm != "aws:kms" {
		t.Fatalf("expected encryption algorithm from subresource details, got %#v", record.Fields)
	}
	if keyID, _ := record.Fields["encryption_key_id"].(string); keyID != "kms:key:logs" {
		t.Fatalf("expected encryption key id from subresource details, got %#v", record.Fields)
	}
}

func TestMaterializeBucketLoggingFacetUsesBucketPostureAndSubresourceDetails(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	bucket := &Node{
		ID:         "arn:aws:s3:::logs",
		Kind:       NodeKindBucket,
		CreatedAt:  now,
		UpdatedAt:  now,
		Properties: map[string]any{"logging_enabled": true},
	}
	config := &Node{
		ID:        "bucket_logging_config:logs",
		Kind:      NodeKindBucketLoggingConfig,
		CreatedAt: now,
		UpdatedAt: now,
		Properties: map[string]any{
			"logging_enabled":       false,
			"logging_target_bucket": "central-audit",
		},
	}
	g.AddNode(bucket)
	g.AddNode(config)
	g.AddEdge(&Edge{
		ID:        "bucket-logging-config",
		Source:    config.ID,
		Target:    bucket.ID,
		Kind:      EdgeKindConfigures,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})

	def, ok := GetEntityFacetDefinition("bucket_logging")
	if !ok {
		t.Fatal("expected bucket_logging facet definition")
	}

	record, materialized := materializeBucketLoggingFacet(g, bucket, now, now, def, nil)
	if !materialized {
		t.Fatal("expected bucket logging facet to materialize")
	}
	if record.Assessment != "pass" {
		t.Fatalf("expected bucket posture to drive pass assessment, got %#v", record)
	}
	if enabled, _ := record.Fields["logging_enabled"].(bool); !enabled {
		t.Fatalf("expected logging_enabled to come from bucket posture, got %#v", record.Fields)
	}
	if targetBucket, _ := record.Fields["logging_target_bucket"].(string); targetBucket != "central-audit" {
		t.Fatalf("expected logging target bucket from subresource details, got %#v", record.Fields)
	}
}

func TestMaterializeBucketVersioningFacetUsesBucketPostureAndSubresourceDetails(t *testing.T) {
	now := time.Now().UTC()
	g := New()
	bucket := &Node{
		ID:         "arn:aws:s3:::logs",
		Kind:       NodeKindBucket,
		CreatedAt:  now,
		UpdatedAt:  now,
		Properties: map[string]any{"versioning_status": "Enabled"},
	}
	config := &Node{
		ID:        "bucket_versioning_config:logs",
		Kind:      NodeKindBucketVersioningConfig,
		CreatedAt: now,
		UpdatedAt: now,
		Properties: map[string]any{
			"versioning_status": "Disabled",
			"mfa_delete":        true,
		},
	}
	g.AddNode(bucket)
	g.AddNode(config)
	g.AddEdge(&Edge{
		ID:        "bucket-versioning-config",
		Source:    config.ID,
		Target:    bucket.ID,
		Kind:      EdgeKindConfigures,
		Effect:    EdgeEffectAllow,
		CreatedAt: now,
	})

	def, ok := GetEntityFacetDefinition("bucket_versioning")
	if !ok {
		t.Fatal("expected bucket_versioning facet definition")
	}

	record, materialized := materializeBucketVersioningFacet(g, bucket, now, now, def, nil)
	if !materialized {
		t.Fatal("expected bucket versioning facet to materialize")
	}
	if record.Assessment != "pass" {
		t.Fatalf("expected bucket posture to drive pass assessment, got %#v", record)
	}
	if status, _ := record.Fields["versioning_status"].(string); status != "enabled" {
		t.Fatalf("expected versioning status to come from bucket posture, got %#v", record.Fields)
	}
	if mfaDelete, _ := record.Fields["mfa_delete"].(bool); !mfaDelete {
		t.Fatalf("expected mfa_delete detail to come from subresource properties, got %#v", record.Fields)
	}
}
