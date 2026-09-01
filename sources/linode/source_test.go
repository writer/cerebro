package linode

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestIssueFamilyIsRetiredFromGoSource(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"family":    familyIssue,
		"token":     "synthetic-test-token",
	}), nil)
	if err == nil {
		t.Fatal("Go Linode issue read unexpectedly remained available")
	}
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Read(issue) error = %v, want invalid configuration", err)
	}
}
