package sourceregistry

import "testing"

func TestBuiltin(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	source, ok := registry.Get("github")
	if !ok {
		t.Fatal("Get(github) = false, want true")
	}
	if source.Spec().Name != "GitHub" {
		t.Fatalf("Spec().Name = %q, want %q", source.Spec().Name, "GitHub")
	}
}
