package graphingest

import "testing"

func TestSanitizeLogValueStripsNewlines(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain value unchanged", input: "run-123", want: "run-123"},
		{name: "newline forgery neutralized", input: "run-123\nFAKE level=error injected", want: "run-123 FAKE level=error injected"},
		{name: "carriage return neutralized", input: "run-123\r\nmalicious", want: "run-123  malicious"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLogValue(tc.input); got != tc.want {
				t.Fatalf("sanitizeLogValue(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
