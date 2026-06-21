package sourcecdk

import "testing"

func TestFirstOpenCIDR(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "nil", values: nil, want: ""},
		{name: "empty", values: []string{}, want: ""},
		{name: "ipv4 any", values: []string{"10.0.0.0/8", "0.0.0.0/0"}, want: "0.0.0.0/0"},
		{name: "ipv6 any", values: []string{"::/0"}, want: "::/0"},
		{name: "trims whitespace", values: []string{"  0.0.0.0/0  "}, want: "0.0.0.0/0"},
		{name: "first match wins", values: []string{"::/0", "0.0.0.0/0"}, want: "::/0"},
		{name: "no open range", values: []string{"10.0.0.0/8", "192.168.0.0/16"}, want: ""},
		{name: "host route is not open", values: []string{"0.0.0.0/32"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FirstOpenCIDR(tc.values); got != tc.want {
				t.Fatalf("FirstOpenCIDR(%v) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}
