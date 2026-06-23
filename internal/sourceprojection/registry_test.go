package sourceprojection

import (
	"testing"
)

type stubHandler struct {
	prefixes []string
}

func (s *stubHandler) Handles() []string { return s.prefixes }

func TestRegistry_RegisterAndLookupExact(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"aws.s3_bucket"}}
	r.Register(h)

	got, ok := r.Lookup("aws.s3_bucket")
	if !ok {
		t.Fatal("expected handler for exact kind")
	}
	if got != h {
		t.Fatal("returned handler does not match registered handler")
	}
}

func TestRegistry_LookupPrefixMatch(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"aws."}}
	r.Register(h)

	got, ok := r.Lookup("aws.ec2_instance")
	if !ok {
		t.Fatal("expected handler via prefix match")
	}
	if got != h {
		t.Fatal("returned handler does not match registered handler")
	}
}

func TestRegistry_LookupMissing(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := &stubHandler{prefixes: []string{"gcp.compute"}}
	r.Register(h)

	_, ok := r.Lookup("azure.vm")
	if ok {
		t.Fatal("expected no handler for unregistered kind")
	}
}

func TestRegistry_MultiplePrefixes(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	awsHandler := &stubHandler{prefixes: []string{"aws."}}
	gcpHandler := &stubHandler{prefixes: []string{"gcp."}}
	r.Register(awsHandler)
	r.Register(gcpHandler)

	got, ok := r.Lookup("aws.lambda_function")
	if !ok {
		t.Fatal("expected handler for aws kind")
	}
	if got != awsHandler {
		t.Fatal("expected aws handler")
	}

	got, ok = r.Lookup("gcp.cloud_run_service")
	if !ok {
		t.Fatal("expected handler for gcp kind")
	}
	if got != gcpHandler {
		t.Fatal("expected gcp handler")
	}
}

func TestRegistry_LongestPrefixWins(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	broad := &stubHandler{prefixes: []string{"aws."}}
	specific := &stubHandler{prefixes: []string{"aws.s3"}}
	r.Register(broad)
	r.Register(specific)

	got, ok := r.Lookup("aws.s3_bucket")
	if !ok {
		t.Fatal("expected handler for aws.s3_bucket")
	}
	if got != specific {
		t.Fatal("expected more specific handler to win")
	}

	got, ok = r.Lookup("aws.ec2_instance")
	if !ok {
		t.Fatal("expected handler for aws.ec2_instance")
	}
	if got != broad {
		t.Fatal("expected broad handler for non-s3 kind")
	}
}

func TestRegistry_RegisterNilHandler(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r.Register(nil)

	_, ok := r.Lookup("anything")
	if ok {
		t.Fatal("expected no handler after registering nil")
	}
}

func TestRegistry_LookupOnNilRegistry(t *testing.T) {
	var r *Registry
	_, ok := r.Lookup("aws.s3_bucket")
	if ok {
		t.Fatal("expected no handler on nil registry")
	}
}
