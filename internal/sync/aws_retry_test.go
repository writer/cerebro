package sync

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestAWSRetryDelayBounds(t *testing.T) {
	delay := awsRetryDelay(-1)
	if delay < awsRetryBaseDelay/2 || delay > awsRetryBaseDelay {
		t.Fatalf("unexpected low-attempt delay %s", delay)
	}

	delay = awsRetryDelay(20)
	if delay < 15*time.Second || delay > 30*time.Second {
		t.Fatalf("unexpected capped delay %s", delay)
	}
}

func TestRandomInt63nInvalidMax(t *testing.T) {
	if got := randomInt63n(0); got != 0 {
		t.Fatalf("expected zero for invalid max, got %d", got)
	}
	if got := randomInt63n(-5); got != 0 {
		t.Fatalf("expected zero for negative max, got %d", got)
	}
}

func TestIsAWSRateLimitError(t *testing.T) {
	if isAWSRateLimitError(nil) {
		t.Fatalf("nil error should not classify as rate limit")
	}
	if !isAWSRateLimitError(&smithy.GenericAPIError{Code: "SlowDown"}) {
		t.Fatalf("expected SlowDown to classify as rate limit")
	}
	if !isAWSRateLimitError(&smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 429}},
		Err:      errors.New("too many requests"),
	}) {
		t.Fatalf("expected http 429 to classify as rate limit")
	}
}

func TestLogAWSPageDurationIncludesSlowFlag(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	logAWSPageDuration(logger, "ec2", "DescribeInstances", 2, 6*time.Second, 25)

	out := buf.String()
	if !strings.Contains(out, "slow=true") {
		t.Fatalf("expected slow=true in log output, got %q", out)
	}
}

func TestSleepWithContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := sleepWithContext(ctx, 10*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestSleepWithContextSleepsSuccessfully(t *testing.T) {
	if err := sleepWithContext(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("expected successful sleep, got %v", err)
	}
}
