package envutil

import (
	"testing"
	"time"
)

func TestGet(t *testing.T) {
	t.Setenv("ENVUTIL_GET", "value")
	if got := Get("ENVUTIL_GET", "fallback"); got != "value" {
		t.Fatalf("expected value, got %q", got)
	}
	if got := Get("ENVUTIL_GET_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
}

func TestGetInt(t *testing.T) {
	t.Setenv("ENVUTIL_INT", "42")
	if got := GetInt("ENVUTIL_INT", 7); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	t.Setenv("ENVUTIL_INT", "invalid")
	if got := GetInt("ENVUTIL_INT", 7); got != 7 {
		t.Fatalf("expected fallback 7, got %d", got)
	}
}

func TestGetBool(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{value: "true", expected: true},
		{value: "1", expected: true},
		{value: "yes", expected: true},
		{value: "false", expected: false},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("ENVUTIL_BOOL", tc.value)
			if got := GetBool("ENVUTIL_BOOL", false); got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}

	if got := GetBool("ENVUTIL_BOOL_MISSING", true); !got {
		t.Fatalf("expected fallback true for missing env")
	}
}

func TestGetDuration(t *testing.T) {
	t.Setenv("ENVUTIL_DURATION", "5m")
	if got := GetDuration("ENVUTIL_DURATION", time.Second); got != 5*time.Minute {
		t.Fatalf("expected 5m, got %s", got)
	}
	t.Setenv("ENVUTIL_DURATION", "bad")
	if got := GetDuration("ENVUTIL_DURATION", time.Second); got != time.Second {
		t.Fatalf("expected fallback 1s, got %s", got)
	}
}

func TestNormalizePrivateKey(t *testing.T) {
	input := "-----BEGIN KEY-----\\nline1\\nline2\\n-----END KEY-----\r\n"
	got := NormalizePrivateKey(input)
	want := "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----"
	if got != want {
		t.Fatalf("unexpected normalized key:\nwant: %q\ngot:  %q", want, got)
	}
}
