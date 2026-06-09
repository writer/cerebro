package bootstrap

import (
	"math"
	"testing"
)

func TestMCPNormalizeLimitValueClampsLargeUnsignedValues(t *testing.T) {
	cases := []struct {
		name         string
		limit        uint32
		defaultLimit int
		maxLimit     int
		want         int
	}{
		{name: "zero returns default", limit: 0, defaultLimit: 25, maxLimit: 100, want: 25},
		{name: "within bound preserved", limit: 10, defaultLimit: 25, maxLimit: 100, want: 10},
		{name: "above bound clamped", limit: 1000, defaultLimit: 25, maxLimit: 100, want: 100},
		{name: "max uint32 clamped", limit: math.MaxUint32, defaultLimit: 25, maxLimit: 100, want: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mcpNormalizeLimitValue(tc.limit, tc.defaultLimit, tc.maxLimit); got != tc.want {
				t.Fatalf("mcpNormalizeLimitValue(%d) = %d, want %d", tc.limit, got, tc.want)
			}
		})
	}
}

func TestMCPBoundedLimitClampsLargeUnsignedValues(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  int
	}{
		{name: "missing returns default", value: nil, want: 25},
		{name: "within bound preserved", value: "10", want: 10},
		{name: "above bound clamped", value: "1000", want: 100},
		{name: "max uint32 clamped", value: "4294967295", want: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{}
			if tc.value != nil {
				args["limit"] = tc.value
			}
			got, err := mcpBoundedLimit(args, "limit", 25, 100)
			if err != nil {
				t.Fatalf("mcpBoundedLimit: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mcpBoundedLimit(%v) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}
