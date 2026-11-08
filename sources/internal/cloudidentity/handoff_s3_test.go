package cloudidentitysource

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func newTestS3Publisher(t *testing.T, server *httptest.Server) *s3HandoffPublisher {
	t.Helper()
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		BaseEndpoint: awssdk.String(server.URL),
		UsePathStyle: true,
	})
	return &s3HandoffPublisher{client: client}
}

// TestS3HandoffPublisherSendsConditionalCreate pins the "conditional create
// (If-None-Match: *)" contract requirement against a real HTTP request/
// response cycle, not a mocked SDK call.
func TestS3HandoffPublisherSendsConditionalCreate(t *testing.T) {
	var gotIfNoneMatch, gotMethod, gotPath, gotContentEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentEncoding = r.Header.Get("Content-Encoding")
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	publisher := newTestS3Publisher(t, server)
	err := publisher.Publish(context.Background(), "intake-bucket", "us-east-1", "cloud-identity/security/writer/key.json.gz", []byte("body"))
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q, want PUT", gotMethod)
	}
	if gotIfNoneMatch != "*" {
		t.Fatalf("If-None-Match = %q, want *", gotIfNoneMatch)
	}
	if gotContentEncoding != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", gotContentEncoding)
	}
	if gotPath == "" {
		t.Fatal("expected a non-empty request path")
	}
}

// TestS3HandoffPublisherTreatsPreconditionFailedAsSuccess pins idempotent
// republish: the content-addressed key already existing is success, not an
// error, since the exact bundle for this collection pass was already
// durably published.
func TestS3HandoffPublisherTreatsPreconditionFailedAsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer server.Close()

	publisher := newTestS3Publisher(t, server)
	if err := publisher.Publish(context.Background(), "intake-bucket", "us-east-1", "cloud-identity/security/writer/key.json.gz", []byte("body")); err != nil {
		t.Fatalf("Publish() error = %v, want nil for a 412 precondition failure", err)
	}
}

func TestS3HandoffPublisherSurfacesOtherFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	publisher := newTestS3Publisher(t, server)
	if err := publisher.Publish(context.Background(), "intake-bucket", "us-east-1", "cloud-identity/security/writer/key.json.gz", []byte("body")); err == nil {
		t.Fatal("Publish() error = nil, want an error for a 403 response")
	}
}
