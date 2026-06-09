package kubernetes

import "testing"

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "kubernetes" {
		t.Fatalf("Spec().Id = %q, want kubernetes", got)
	}
}
