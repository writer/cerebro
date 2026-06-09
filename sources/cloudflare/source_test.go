package cloudflare

import "testing"

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "cloudflare" {
		t.Fatalf("Spec().Id = %q, want cloudflare", got)
	}
}
