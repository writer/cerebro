package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newTestService(rt http.RoundTripper) *Service {
	svc := &Service{
		client:    &http.Client{Transport: rt},
		backoffFn: func(context.Context, int) error { return nil },
	}
	return svc
}

func TestDoWithRetrySuccess(t *testing.T) {
	attempts := 0
	svc := newTestService(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}))

	resp, err := svc.doWithRetry(context.Background(), http.MethodGet, "http://example.com", nil, nil)
	if err != nil {
		t.Fatalf("expected success, got error %v", err)
	}
	resp.Body.Close()
	if attempts != 1 {
		t.Fatalf("expected single attempt, got %d", attempts)
	}
}

func TestDoWithRetryRetriesOnServerError(t *testing.T) {
	attempts := 0
	svc := newTestService(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("oops")),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}))

	resp, err := svc.doWithRetry(context.Background(), http.MethodGet, "http://example.com", nil, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	resp.Body.Close()
	if attempts != 2 {
		t.Fatalf("expected two attempts, got %d", attempts)
	}
}

func TestDoWithRetryNonRetryableStatus(t *testing.T) {
	svc := newTestService(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewBufferString("invalid payload")),
		}, nil
	}))

	_, err := svc.doWithRetry(context.Background(), http.MethodPost, "http://example.com", []byte("{}"), nil)
	if err == nil {
		t.Fatalf("expected error for non-retryable status")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected error to mention status code, got %v", err)
	}
}

func TestDoWithRetryRespectsContextCancellation(t *testing.T) {
	attempts := 0
	svc := newTestService(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return nil, context.DeadlineExceeded
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.backoffFn = func(context.Context, int) error { return context.Canceled }

	if _, err := svc.doWithRetry(ctx, http.MethodGet, "http://example.com", nil, nil); err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if attempts != 1 {
		t.Fatalf("expected single attempt after cancellation, got %d", attempts)
	}
}
