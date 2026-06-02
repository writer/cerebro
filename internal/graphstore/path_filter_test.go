package graphstore

import "testing"

func TestSuppressTwoHopPath(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
		want   bool
	}{
		{name: "container finding gravity well", first: "belongs_to", second: "has_finding", want: true},
		{name: "identity finding gravity well", first: "represents", second: "has_finding", want: true},
		{name: "package vulnerability gravity well", first: "contains", second: "affected_by", want: true},
		{name: "activity fanout first hop", first: "acted_on", second: "belongs_to", want: true},
		{name: "activity fanout second hop", first: "has_identifier", second: "acted_on", want: true},
		{name: "direct vulnerability signal", first: "affected_by", second: "has_finding", want: false},
		{name: "attack path signal", first: "can_perform", second: "has_finding", want: false},
		{name: "ownership signal", first: "owned_by", second: "has_finding", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SuppressTwoHopPath(test.first, test.second); got != test.want {
				t.Fatalf("SuppressTwoHopPath(%q, %q) = %v, want %v", test.first, test.second, got, test.want)
			}
		})
	}
}
