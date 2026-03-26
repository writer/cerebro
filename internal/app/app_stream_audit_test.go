package app

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestParseAuditMutationCloudEventUsesTableAwareResourceIDs(t *testing.T) {
	evt := events.CloudEvent{
		ID:     "evt-audit-multi-provider-1",
		Source: "urn:test:audit",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"mutations": []any{
				map[string]any{
					"table_name": "aws_ec2_security_groups",
					"payload": map[string]any{
						"arn":      "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
						"_cq_id":   "cq-sg-123",
						"group_id": "sg-123",
					},
				},
				map[string]any{
					"table_name": "gcp_compute_firewalls",
					"payload": map[string]any{
						"self_link": "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1",
						"_cq_id":    "cq-fw-1",
						"id":        "1234567890",
					},
				},
				map[string]any{
					"table_name": "azure_network_security_groups",
					"payload": map[string]any{
						"id":     "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
						"_cq_id": "cq-nsg-1",
						"name":   "nsg-1",
					},
				},
			},
		},
	}

	result, err := parseAuditMutationCloudEvent(evt)
	if err != nil {
		t.Fatalf("parseAuditMutationCloudEvent failed: %v", err)
	}
	mutations := result.Mutations
	if len(mutations) != 3 {
		t.Fatalf("expected 3 mutations, got %d", len(mutations))
	}

	if got := mutations[0].ResourceID; got != "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123" {
		t.Fatalf("expected AWS resource ID to prefer arn, got %q", got)
	}
	if got := mutations[1].ResourceID; got != "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1" {
		t.Fatalf("expected GCP resource ID to prefer self_link, got %q", got)
	}
	if got := mutations[2].ResourceID; got != "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1" {
		t.Fatalf("expected Azure resource ID to prefer id, got %q", got)
	}
}

func TestParseAuditMutationCloudEventSkipsInvalidBatchRecordsAndNormalizesDeleteSynonyms(t *testing.T) {
	evt := events.CloudEvent{
		ID:     "evt-audit-batch-2",
		Source: "urn:test:audit",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 13, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"mutations": []any{
				map[string]any{
					"payload": map[string]any{"id": "ignored"},
				},
				map[string]any{
					"table_name":  "aws_ec2_security_groups",
					"change_type": "modified",
					"payload":     map[string]any{},
				},
				map[string]any{
					"table_name":  "aws_ec2_security_groups",
					"change_type": "deleted",
					"payload":     map[string]any{},
				},
			},
		},
	}

	result, err := parseAuditMutationCloudEvent(evt)
	if err != nil {
		t.Fatalf("parseAuditMutationCloudEvent failed: %v", err)
	}
	if result.Dropped != 2 {
		t.Fatalf("expected 2 dropped records, got %d", result.Dropped)
	}
	if len(result.Mutations) != 1 {
		t.Fatalf("expected 1 valid mutation, got %d", len(result.Mutations))
	}
	if got := result.Mutations[0].ChangeType; got != "removed" {
		t.Fatalf("expected deleted synonym to normalize to removed, got %q", got)
	}
	if got := result.Mutations[0].ResourceID; got != "" {
		t.Fatalf("expected removal mutation to allow empty resource_id, got %q", got)
	}
}

func TestHandleAuditMutationCloudEventSkipsGraphApplyWithoutBuilder(t *testing.T) {
	store := &warehouse.MemoryWarehouse{
		QueryFunc: func(ctx context.Context, query string, args ...any) (*warehouse.QueryResult, error) {
			t.Fatalf("unexpected warehouse query without graph builder: %q", query)
			return nil, nil
		},
	}
	application := &App{Warehouse: store}

	evt := events.CloudEvent{
		ID:     "evt-audit-runtime-1",
		Source: "urn:test:audit",
		Type:   "aws.cloudtrail.asset.changed",
		Time:   time.Date(2026, 3, 14, 14, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"mutations": []any{
				map[string]any{
					"table_name":  "aws_s3_buckets",
					"change_type": "added",
					"payload": map[string]any{
						"arn":    "arn:aws:s3:::audit-bucket",
						"name":   "audit-bucket",
						"region": "us-east-1",
					},
				},
			},
		},
	}

	if err := application.handleAuditMutationCloudEvent(context.Background(), evt); err != nil {
		t.Fatalf("handleAuditMutationCloudEvent failed: %v", err)
	}
	if len(store.CDCBatches) != 1 {
		t.Fatalf("expected one CDC batch, got %d", len(store.CDCBatches))
	}
	if len(store.Queries) != 0 {
		t.Fatalf("expected no warehouse graph queries, got %#v", store.Queries)
	}
}
