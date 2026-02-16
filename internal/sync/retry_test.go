package sync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/smithy-go"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyAWSError(t *testing.T) {
	if classifyAWSError(&smithy.GenericAPIError{Code: "ThrottlingException"}) != retryThrottle {
		t.Fatalf("expected throttle classification")
	}
	if classifyAWSError(&smithy.GenericAPIError{Code: "AccessDenied"}) != retryAuth {
		t.Fatalf("expected auth classification")
	}
	if classifyAWSError(timeoutError{}) != retryTransient {
		t.Fatalf("expected transient classification")
	}
}

func TestClassifyGCPError(t *testing.T) {
	if classifyGCPError(&googleapi.Error{Code: 429}) != retryThrottle {
		t.Fatalf("expected throttle classification")
	}
	if classifyGCPError(&googleapi.Error{Code: 403}) != retryAuth {
		t.Fatalf("expected auth classification")
	}
	if classifyGCPError(status.Error(codes.ResourceExhausted, "rate")) != retryThrottle {
		t.Fatalf("expected gRPC throttle classification")
	}
	if classifyGCPError(errors.New("timeout")) != retryTransient {
		t.Fatalf("expected transient classification")
	}
}

func TestClassifyAzureError(t *testing.T) {
	if classifyAzureError(&azcore.ResponseError{StatusCode: 429, ErrorCode: "TooManyRequests"}) != retryThrottle {
		t.Fatalf("expected throttle classification")
	}
	if classifyAzureError(&azcore.ResponseError{StatusCode: 403}) != retryAuth {
		t.Fatalf("expected auth classification")
	}
	if classifyAzureError(&azcore.ResponseError{StatusCode: 500}) != retryTransient {
		t.Fatalf("expected transient classification")
	}
}

func TestRetryFetchReturnsRowsOnPartialError(t *testing.T) {
	ctx := context.Background()
	expectedRows := []map[string]interface{}{{"_cq_id": "r1"}}

	rows, err := retryFetch(
		ctx,
		nil,
		retryOptions{Attempts: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
		nil,
		"test",
		nil,
		func(error) retryClass { return retryNone },
		nil,
		func() ([]map[string]interface{}, error) {
			return expectedRows, newPartialFetchError(errors.New("page failed"))
		},
	)

	if err == nil {
		t.Fatalf("expected partial error")
	}
	if !isPartialFetchError(err) {
		t.Fatalf("expected partial fetch error type")
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}
