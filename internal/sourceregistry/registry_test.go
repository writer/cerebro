package sourceregistry

import "testing"

func TestBuiltin(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	github, ok := registry.Get("github")
	if !ok {
		t.Fatal("Get(github) = false, want true")
	}
	if github.Spec().Name != "GitHub" {
		t.Fatalf("github Spec().Name = %q, want %q", github.Spec().Name, "GitHub")
	}
	googleWorkspace, ok := registry.Get("google_workspace")
	if !ok {
		t.Fatal("Get(google_workspace) = false, want true")
	}
	if googleWorkspace.Spec().Name != "Google Workspace" {
		t.Fatalf("google_workspace Spec().Name = %q, want %q", googleWorkspace.Spec().Name, "Google Workspace")
	}
	okta, ok := registry.Get("okta")
	if !ok {
		t.Fatal("Get(okta) = false, want true")
	}
	if okta.Spec().Name != "Okta" {
		t.Fatalf("okta Spec().Name = %q, want %q", okta.Spec().Name, "Okta")
	}
	sdk, ok := registry.Get("sdk")
	if !ok {
		t.Fatal("Get(sdk) = false, want true")
	}
	if sdk.Spec().Name != "SDK Push Source" {
		t.Fatalf("sdk Spec().Name = %q, want %q", sdk.Spec().Name, "SDK Push Source")
	}
}
