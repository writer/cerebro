package oktaevent

import "testing"

func TestAssignmentCursor(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantPhase  string
		wantCursor string
	}{
		{name: "empty", raw: "", wantPhase: "users", wantCursor: ""},
		{name: "bare cursor defaults to users", raw: "abc123", wantPhase: "users", wantCursor: "abc123"},
		{name: "users phase", raw: "users:cursor-1", wantPhase: "users", wantCursor: "cursor-1"},
		{name: "groups phase", raw: "groups:cursor-2", wantPhase: "groups", wantCursor: "cursor-2"},
		{name: "unknown phase falls back to users with raw value", raw: "widgets:cursor-3", wantPhase: "users", wantCursor: "widgets:cursor-3"},
		{name: "trims surrounding whitespace", raw: "  groups : cursor-4 ", wantPhase: "groups", wantCursor: "cursor-4"},
		{name: "empty cursor after phase", raw: "groups:", wantPhase: "groups", wantCursor: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phase, cursor := AssignmentCursor(tc.raw)
			if phase != tc.wantPhase {
				t.Errorf("AssignmentCursor(%q) phase = %q, want %q", tc.raw, phase, tc.wantPhase)
			}
			if cursor != tc.wantCursor {
				t.Errorf("AssignmentCursor(%q) cursor = %q, want %q", tc.raw, cursor, tc.wantCursor)
			}
		})
	}
}

func TestPhasedCursor(t *testing.T) {
	cases := []struct {
		name   string
		phase  string
		cursor string
		want   string
	}{
		{name: "empty cursor returns empty", phase: "users", cursor: "", want: ""},
		{name: "whitespace cursor returns empty", phase: "users", cursor: "   ", want: ""},
		{name: "users phase", phase: "users", cursor: "abc", want: "users:abc"},
		{name: "groups phase", phase: "groups", cursor: "def", want: "groups:def"},
		{name: "trims phase and cursor", phase: " groups ", cursor: " def ", want: "groups:def"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PhasedCursor(tc.phase, tc.cursor); got != tc.want {
				t.Errorf("PhasedCursor(%q, %q) = %q, want %q", tc.phase, tc.cursor, got, tc.want)
			}
		})
	}
}

func TestAssignmentCursorRoundTrip(t *testing.T) {
	for _, phase := range []string{"users", "groups"} {
		encoded := PhasedCursor(phase, "cursor-value")
		gotPhase, gotCursor := AssignmentCursor(encoded)
		if gotPhase != phase || gotCursor != "cursor-value" {
			t.Errorf("round trip for %q = (%q, %q), want (%q, %q)", phase, gotPhase, gotCursor, phase, "cursor-value")
		}
	}
}
