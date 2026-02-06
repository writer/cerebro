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
