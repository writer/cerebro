package graph

import "testing"

func TestParseStoreBackend(t *testing.T) {
	tests := []struct {
		input string
		want  StoreBackend
		valid bool
	}{
		{input: "", want: StoreBackendMemory, valid: true},
		{input: "memory", want: StoreBackendMemory, valid: true},
		{input: " Neptune ", want: StoreBackendNeptune, valid: true},
		{input: "spanner", want: StoreBackendSpanner, valid: true},
		{input: "unknown", want: StoreBackend("unknown"), valid: false},
	}
	for _, tc := range tests {
		got := ParseStoreBackend(tc.input)
		if got != tc.want {
			t.Fatalf("ParseStoreBackend(%q) = %q, want %q", tc.input, got, tc.want)
		}
		if got.Valid() != tc.valid {
			t.Fatalf("ParseStoreBackend(%q).Valid() = %v, want %v", tc.input, got.Valid(), tc.valid)
		}
	}
}
