package sourcecdk

import "testing"

func TestJSONScalarFlattened(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{name: "nil", value: nil, want: ""},
		{name: "trims string", value: "  hi  ", want: "hi"},
		{name: "float without exponent", value: float64(42), want: "42"},
		{name: "float fractional", value: 3.5, want: "3.5"},
		{name: "bool", value: true, want: "true"},
		{name: "slice joins non-empty", value: []any{"a", "", "b", float64(2)}, want: "a,b,2"},
		{name: "nested slice", value: []any{"a", []any{"b", "c"}}, want: "a,b,c"},
		{name: "default via sprint", value: 7, want: "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (JSONScalar{Value: tc.value}).Flattened(); got != tc.want {
				t.Fatalf("JSONScalar{%#v}.Flattened() = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
