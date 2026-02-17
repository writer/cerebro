package snowflake

import (
	"testing"
	"time"
)

func TestCDCEvent_Fields(t *testing.T) {
	now := time.Now().UTC()
	e := CDCEvent{
		EventID:     "evt-001",
		TableName:   "aws_s3_buckets",
		ResourceID:  "arn:aws:s3:::my-bucket",
		ChangeType:  "update",
		Provider:    "aws",
		Region:      "us-east-1",
		AccountID:   "123456789",
		PayloadHash: "abc123",
		EventTime:   now,
	}

	if e.EventID != "evt-001" {
		t.Errorf("EventID = %q", e.EventID)
	}
	if e.TableName != "aws_s3_buckets" {
		t.Errorf("TableName = %q", e.TableName)
	}
	if e.ChangeType != "update" {
		t.Errorf("ChangeType = %q", e.ChangeType)
	}
	if e.EventTime != now {
		t.Errorf("EventTime mismatch")
	}
}

func TestAssetFilter_Fields(t *testing.T) {
	since := time.Now().Add(-1 * time.Hour)
	f := AssetFilter{
		Provider: "aws",
		Account:  "123",
		Region:   "us-east-1",
		Limit:    50,
		Offset:   10,
		Since:    since,
		SinceID:  "abc",
	}

	if f.Provider != "aws" {
		t.Errorf("Provider = %q", f.Provider)
	}
	if f.Limit != 50 {
		t.Errorf("Limit = %d", f.Limit)
	}
	if f.Since != since {
		t.Errorf("Since mismatch")
	}
}

func TestAsset_Fields(t *testing.T) {
	a := Asset{
		ID:       "arn:aws:s3:::bucket",
		Type:     "s3_bucket",
		Provider: "aws",
		Account:  "123",
		Region:   "us-east-1",
		Name:     "my-bucket",
		Properties: map[string]interface{}{
			"public": true,
		},
	}

	if a.ID != "arn:aws:s3:::bucket" {
		t.Errorf("ID = %q", a.ID)
	}
	if a.Properties["public"] != true {
		t.Errorf("Properties.public = %v", a.Properties["public"])
	}
}

func TestCDCEventFromRow_LowercaseKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	row := map[string]interface{}{
		"event_id":     "evt-123",
		"table_name":   "k8s_core_service_accounts",
		"resource_id":  "orbstack:kube-system:default",
		"change_type":  "added",
		"provider":     "k8s",
		"region":       "orbstack",
		"account_id":   "",
		"payload_hash": "hash-1",
		"event_time":   now,
	}

	event := cdcEventFromRow(row)
	if event.EventID != "evt-123" {
		t.Fatalf("unexpected event id: %q", event.EventID)
	}
	if event.TableName != "k8s_core_service_accounts" {
		t.Fatalf("unexpected table name: %q", event.TableName)
	}
	if event.ChangeType != "added" {
		t.Fatalf("unexpected change type: %q", event.ChangeType)
	}
	if !event.EventTime.Equal(now) {
		t.Fatalf("unexpected event time: %v", event.EventTime)
	}
}

func TestCDCEventFromRow_UppercaseKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	row := map[string]interface{}{
		"EVENT_ID":     "evt-999",
		"TABLE_NAME":   "aws_iam_users",
		"RESOURCE_ID":  "arn:aws:iam::123:user/test",
		"CHANGE_TYPE":  "modified",
		"PROVIDER":     "aws",
		"REGION":       "us-east-1",
		"ACCOUNT_ID":   "123",
		"PAYLOAD_HASH": "hash-9",
		"EVENT_TIME":   now,
	}

	event := cdcEventFromRow(row)
	if event.EventID != "evt-999" {
		t.Fatalf("unexpected event id: %q", event.EventID)
	}
	if event.ChangeType != "modified" {
		t.Fatalf("unexpected change type: %q", event.ChangeType)
	}
	if !event.EventTime.Equal(now) {
		t.Fatalf("unexpected event time: %v", event.EventTime)
	}
}
