package sourcecdk

import (
	"testing"
	"time"
)

func TestWatermarkString(t *testing.T) {
	early := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		watermark time.Time
		fallback  time.Time
		want      string
	}{
		{name: "prefers later fallback", watermark: early, fallback: late, want: late.Format(time.RFC3339Nano)},
		{name: "keeps later watermark", watermark: late, fallback: early, want: late.Format(time.RFC3339Nano)},
		{name: "keeps watermark on tie", watermark: late, fallback: late, want: late.Format(time.RFC3339Nano)},
		{name: "uses fallback when watermark zero", watermark: time.Time{}, fallback: late, want: late.Format(time.RFC3339Nano)},
		{name: "keeps watermark when fallback zero", watermark: late, fallback: time.Time{}, want: late.Format(time.RFC3339Nano)},
		{name: "empty when both zero", watermark: time.Time{}, fallback: time.Time{}, want: ""},
		{name: "renders as utc", watermark: time.Date(2026, 6, 15, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600)), fallback: time.Time{}, want: late.Format(time.RFC3339Nano)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WatermarkString(tc.watermark, tc.fallback); got != tc.want {
				t.Fatalf("WatermarkString(%v, %v) = %q, want %q", tc.watermark, tc.fallback, got, tc.want)
			}
		})
	}
}
