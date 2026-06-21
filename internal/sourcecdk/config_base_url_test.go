package sourcecdk

import (
	"errors"
	"testing"
)

func TestResolveBaseURLConfig(t *testing.T) {
	t.Run("renders base_url from template when unset", func(t *testing.T) {
		cfg := NewConfig(map[string]string{"token": "abc"})
		got, err := ResolveBaseURLConfig("vault", "https://${config.token}.example", cfg, []string{"token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v, _ := got.Lookup("base_url"); v != "https://abc.example" {
			t.Fatalf("base_url = %q", v)
		}
	})

	t.Run("keeps explicit base_url and ignores template", func(t *testing.T) {
		cfg := NewConfig(map[string]string{"base_url": "https://explicit.example", "token": "abc"})
		got, err := ResolveBaseURLConfig("vault", "https://${config.token}.example", cfg, []string{"token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v, _ := got.Lookup("base_url"); v != "https://explicit.example" {
			t.Fatalf("base_url = %q", v)
		}
	})

	t.Run("empty template leaves config unchanged", func(t *testing.T) {
		cfg := NewConfig(map[string]string{"token": "abc"})
		got, err := ResolveBaseURLConfig("vault", "", cfg, []string{"token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v, _ := got.Lookup("base_url"); v != "" {
			t.Fatalf("expected no base_url, got %q", v)
		}
	})

	t.Run("propagates render errors", func(t *testing.T) {
		cfg := NewConfig(map[string]string{})
		if _, err := ResolveBaseURLConfig("vault", "https://${config.token}.example", cfg, []string{"token"}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("want ErrInvalidConfig, got %v", err)
		}
	})
}
