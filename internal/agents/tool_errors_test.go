package agents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestAWSInspectUnsupportedService(t *testing.T) {
	st := &SecurityTools{}

	_, err := st.awsInspect(context.Background(), json.RawMessage(`{"service":"rds","action":"list"}`))
	if err == nil {
		t.Fatal("expected error")
		return
	}

	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T", err)
	}
	if toolErr.Code != "unsupported_service" {
		t.Errorf("expected code unsupported_service, got %s", toolErr.Code)
	}
	if !containsString(toolErr.SupportedServices, "s3") {
		t.Errorf("expected supported services to include s3")
	}
}

func TestHandleS3UnsupportedAction(t *testing.T) {
	st := &SecurityTools{}

	_, err := st.handleS3(context.Background(), aws.Config{Region: "us-east-1"}, "delete-bucket", nil)
	if err == nil {
		t.Fatal("expected error")
		return
	}

	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T", err)
	}
	if toolErr.Code != "unsupported_action" {
		t.Errorf("expected code unsupported_action, got %s", toolErr.Code)
	}
	if !containsString(toolErr.SupportedActions, "list-buckets") {
		t.Errorf("expected supported actions to include list-buckets")
	}
}

func TestGCPInspectUnsupportedService(t *testing.T) {
	st := &SecurityTools{}

	_, err := st.gcpInspect(context.Background(), json.RawMessage(`{"service":"bigquery","action":"list-datasets","project":"test"}`))
	if err == nil {
		t.Fatal("expected error")
		return
	}

	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T", err)
	}
	if toolErr.Code != "unsupported_service" {
		t.Errorf("expected code unsupported_service, got %s", toolErr.Code)
	}
}

func TestInspectCloudResourceUnsupportedProvider(t *testing.T) {
	st := &SecurityTools{}

	_, err := st.InspectCloudResource(context.Background(), InspectCloudResourceParams{
		Resource: "s3://example-bucket",
		Provider: "azure",
		Service:  "s3",
		Action:   "list-buckets",
	})
	if err == nil {
		t.Fatal("expected error")
		return
	}

	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolError, got %T", err)
	}
	if toolErr.Code != "unsupported_provider" {
		t.Errorf("expected code unsupported_provider, got %s", toolErr.Code)
	}
}
