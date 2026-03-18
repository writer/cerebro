package iacrender

import "testing"

func TestHCLStringEscapesInterpolationAndDirectives(t *testing.T) {
	got := HCLString(`repo:${danger} %{ if danger }`)
	want := `"repo:$${danger} %%{ if danger }"`
	if got != want {
		t.Fatalf("HCLString() = %q, want %q", got, want)
	}
}
