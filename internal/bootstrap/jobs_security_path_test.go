package bootstrap

import "testing"

func TestBoolPayloadAcceptsOnlyExplicitTrue(t *testing.T) {
	for _, test := range []struct {
		value any
		want  bool
	}{{true, true}, {" true ", true}, {false, false}, {"yes", false}, {float64(1), false}} {
		if got := boolPayload(map[string]any{"capture": test.value}, "capture"); got != test.want {
			t.Fatalf("boolPayload(%#v) = %t, want %t", test.value, got, test.want)
		}
	}
}
