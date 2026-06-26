package sourcecdk

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJSONScalarString(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"string trimmed", "  hello  ", "hello"},
		{"json number trimmed", json.Number(" 42 "), "42"},
		{"float without exponent", 1500000.0, "1500000"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"nil", nil, ""},
		{"map", map[string]any{"a": 1}, ""},
		{"slice", []any{1, 2}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (JSONScalar{Value: tc.value}).String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJSONFieldString(t *testing.T) {
	values := map[string]any{
		"owner": map[string]any{
			"displayName": "  Ada Lovelace  ",
		},
		"tags": []any{"prod", "", "soc2"},
	}
	object := JSONObject(values)
	if got := object.FieldString("owner"); got != "Ada Lovelace" {
		t.Fatalf("FieldString(owner) = %q, want Ada Lovelace", got)
	}
	if got := object.FieldString("tags"); got != "prod,soc2" {
		t.Fatalf("FieldString(tags) = %q, want prod,soc2", got)
	}
	if got := object.FieldString("missing.path"); got != "" {
		t.Fatalf("FieldString(missing.path) = %q, want empty", got)
	}
	if got := len(object.Array("tags")); got != 3 {
		t.Fatalf("len(Array(tags)) = %d, want 3", got)
	}
}

func TestJSONScalarTime(t *testing.T) {
	layouts := []string{time.RFC3339Nano, "2006-01-02"}

	if got := (JSONScalar{Value: "2023-05-04T01:02:03Z"}).Time(layouts...); !got.Equal(time.Date(2023, 5, 4, 1, 2, 3, 0, time.UTC)) {
		t.Fatalf("rfc3339 Time() = %v", got)
	}
	if got := (JSONScalar{Value: "2023-05-04"}).Time(layouts...); !got.Equal(time.Date(2023, 5, 4, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("date-only Time() = %v", got)
	}
	if got := (JSONScalar{Value: ""}).Time(layouts...); !got.IsZero() {
		t.Fatalf("empty Time() = %v, want zero", got)
	}
	if got := (JSONScalar{Value: "not-a-time"}).Time(layouts...); !got.IsZero() {
		t.Fatalf("unparseable Time() = %v, want zero", got)
	}
}
