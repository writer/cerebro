package oktaasset

import "testing"

func TestThreatInsightOccurredAtFailsClosed(t *testing.T) {
	for _, timestamps := range [][2]string{
		{},
		{"", "1970-01-01T00:00:00Z"},
		{"invalid", "invalid"},
	} {
		if value, err := ThreatInsightOccurredAt(timestamps[0], timestamps[1]); err == nil {
			t.Fatalf("ThreatInsightOccurredAt(%q, %q) = %v, want error", timestamps[0], timestamps[1], value)
		}
	}
}
