package sourcecdk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOAuthTokenCacheReusesTokenUntilLeeway(t *testing.T) {
	cache := NewOAuthTokenCache(time.Minute)
	fetches := 0
	fetch := func(context.Context) (OAuthToken, error) {
		fetches++
		return OAuthToken{Value: "token-1", ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
	}
	for range 3 {
		token, err := cache.Token(context.Background(), "key", fetch)
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if token != "token-1" {
			t.Fatalf("token = %q, want token-1", token)
		}
	}
	if fetches != 1 {
		t.Fatalf("fetches = %d, want 1 (cached reuse)", fetches)
	}
}

func TestOAuthTokenCacheRefetchesWithinLeewayOfExpiry(t *testing.T) {
	cache := NewOAuthTokenCache(time.Hour)
	fetches := 0
	fetch := func(context.Context) (OAuthToken, error) {
		fetches++
		return OAuthToken{Value: "token", ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
	}
	if _, err := cache.Token(context.Background(), "key", fetch); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if _, err := cache.Token(context.Background(), "key", fetch); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if fetches != 2 {
		t.Fatalf("fetches = %d, want 2 (leeway forces refetch)", fetches)
	}
}

func TestOAuthTokenCacheScopesByKey(t *testing.T) {
	cache := NewOAuthTokenCache(time.Minute)
	fetch := func(key string) OAuthTokenFetcher {
		return func(context.Context) (OAuthToken, error) {
			return OAuthToken{Value: "token-" + key, ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
		}
	}
	for _, key := range []string{"a", "b"} {
		token, err := cache.Token(context.Background(), key, fetch(key))
		if err != nil {
			t.Fatalf("Token(%s) error = %v", key, err)
		}
		if want := "token-" + key; token != want {
			t.Fatalf("token = %q, want %q", token, want)
		}
	}
}

func TestOAuthTokenCacheInvalidateForcesRefetch(t *testing.T) {
	cache := NewOAuthTokenCache(time.Minute)
	fetches := 0
	fetch := func(context.Context) (OAuthToken, error) {
		fetches++
		return OAuthToken{Value: "token", ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
	}
	if _, err := cache.Token(context.Background(), "key", fetch); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	cache.Invalidate("key")
	if _, err := cache.Token(context.Background(), "key", fetch); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if fetches != 2 {
		t.Fatalf("fetches = %d, want 2 after Invalidate", fetches)
	}
}

func TestOAuthTokenCacheNilReceiverErrors(t *testing.T) {
	var cache *OAuthTokenCache
	if _, err := cache.Token(context.Background(), "key", func(context.Context) (OAuthToken, error) {
		return OAuthToken{}, nil
	}); err == nil {
		t.Fatal("Token() error = nil, want error for nil cache")
	}
	cache.Invalidate("key") // must not panic
}

func TestOAuthTokenCachePropagatesFetchError(t *testing.T) {
	cache := NewOAuthTokenCache(time.Minute)
	wantErr := context.DeadlineExceeded
	_, err := cache.Token(context.Background(), "key", func(context.Context) (OAuthToken, error) {
		return OAuthToken{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestDecodeOAuthTokenResponse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, err := DecodeOAuthTokenResponse("VulnView", []byte(`{"access_token":"abc","token_type":"Bearer","expires_in":120}`), now, time.Hour)
	if err != nil {
		t.Fatalf("DecodeOAuthTokenResponse() error = %v", err)
	}
	if token.Value != "abc" {
		t.Fatalf("token.Value = %q, want abc", token.Value)
	}
	if want := now.Add(120 * time.Second); !token.ExpiresAt.Equal(want) {
		t.Fatalf("token.ExpiresAt = %v, want %v", token.ExpiresAt, want)
	}
}

func TestDecodeOAuthTokenResponseDefaultsTTLWhenExpiresInMissing(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, err := DecodeOAuthTokenResponse("VulnView", []byte(`{"access_token":"abc"}`), now, time.Hour)
	if err != nil {
		t.Fatalf("DecodeOAuthTokenResponse() error = %v", err)
	}
	if want := now.Add(time.Hour); !token.ExpiresAt.Equal(want) {
		t.Fatalf("token.ExpiresAt = %v, want %v", token.ExpiresAt, want)
	}
}

func TestDecodeOAuthTokenResponseRejectsEmptyAccessToken(t *testing.T) {
	if _, err := DecodeOAuthTokenResponse("VulnView", []byte(`{"access_token":""}`), time.Now(), time.Hour); err == nil {
		t.Fatal("DecodeOAuthTokenResponse() error = nil, want error")
	}
}

func TestDecodeOAuthTokenResponseRejectsNonBearerTokenType(t *testing.T) {
	if _, err := DecodeOAuthTokenResponse("VulnView", []byte(`{"access_token":"abc","token_type":"MAC"}`), time.Now(), time.Hour); err == nil {
		t.Fatal("DecodeOAuthTokenResponse() error = nil, want error")
	}
}

func TestClientCredentialsForm(t *testing.T) {
	form := ClientCredentialsForm("client", "secret", "scope-a scope-b")
	if got := form.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q", got)
	}
	if got := form.Get("client_id"); got != "client" {
		t.Fatalf("client_id = %q", got)
	}
	if got := form.Get("client_secret"); got != "secret" {
		t.Fatalf("client_secret = %q", got)
	}
	if got := form.Get("scope"); got != "scope-a scope-b" {
		t.Fatalf("scope = %q", got)
	}
}

func TestClientCredentialsFormOmitsEmptyScope(t *testing.T) {
	form := ClientCredentialsForm("client", "secret", "")
	if form.Has("scope") {
		t.Fatalf("scope present, want omitted when empty")
	}
}

func TestHashSecretIsStableAndDistinct(t *testing.T) {
	a := HashSecret("secret-one")
	b := HashSecret("secret-one")
	c := HashSecret("secret-two")
	if a != b {
		t.Fatalf("HashSecret not stable: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("HashSecret collided for distinct inputs")
	}
	if a == "secret-one" {
		t.Fatalf("HashSecret returned plaintext input")
	}
}
