package sourcecdk

import (
	"testing"
	"time"
)

func TestResolveCursorOpaque(t *testing.T) {
	occurred := time.Date(2026, 6, 15, 12, 34, 56, 123456789, time.UTC)
	cases := []struct {
		name       string
		next       string
		fallback   string
		occurredAt time.Time
		want       string
	}{
		{name: "prefers trimmed next", next: "  tok-2  ", fallback: "id-9", occurredAt: occurred, want: "tok-2"},
		{name: "falls back to trimmed fallback", next: "   ", fallback: "  id-9  ", occurredAt: occurred, want: "id-9"},
		{name: "falls back to event time", next: "", fallback: "", occurredAt: occurred, want: occurred.Format(time.RFC3339Nano)},
		{name: "renders event time as utc", next: "", fallback: "", occurredAt: time.Date(2026, 6, 15, 14, 34, 56, 0, time.FixedZone("CEST", 2*3600)), want: time.Date(2026, 6, 15, 12, 34, 56, 0, time.UTC).Format(time.RFC3339Nano)},
		{name: "empty when nothing available", next: "  ", fallback: "", occurredAt: time.Time{}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveCursorOpaque(tc.next, tc.fallback, tc.occurredAt); got != tc.want {
				t.Fatalf("ResolveCursorOpaque(%q, %q, %v) = %q, want %q", tc.next, tc.fallback, tc.occurredAt, got, tc.want)
			}
		})
	}
}
