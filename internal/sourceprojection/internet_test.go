package sourceprojection

import "testing"

func TestInternetDomainUsesRegistrableDomain(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "standard domain", raw: "https://app.writer.com/login", want: "writer.com"},
		{name: "multi label public suffix", raw: "api.example.co.uk", want: "example.co.uk"},
		{name: "public suffix only", raw: "co.uk", want: ""},
		{name: "ip address", raw: "203.0.113.10", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := internetDomain(tt.raw); got != tt.want {
				t.Fatalf("internetDomain(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
