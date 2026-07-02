package oneloginapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestTokenCacheDoesNotBlockCachedKeysDuringExchange(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var closeSlowStarted sync.Once
	var releaseSlowOnce sync.Once
	defer releaseSlowOnce.Do(func() { close(releaseSlow) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cached" {
			t.Error("cached token key should not call the token endpoint")
			http.Error(w, "unexpected cached exchange", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/slow" {
			t.Errorf("token path = %q, want /slow", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		closeSlowStarted.Do(func() { close(slowStarted) })
		<-releaseSlow
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "slow-token", "expires_in": 600})
	}))
	defer server.Close()

	cache := &TokenCache{entries: map[string]tokenCacheEntry{
		tokenCacheKey(server.URL+"/cached", "cached-client", "cached-secret"): {
			value:     "cached-token",
			expiresAt: time.Now().Add(time.Hour),
		},
	}}
	slowDone := make(chan error, 1)
	go func() {
		_, err := cache.Token(context.Background(), sourcecdk.NewConfig(map[string]string{
			"token_url":     server.URL + "/slow",
			"client_id":     "slow-client",
			"client_secret": "slow-secret",
		}), true)
		slowDone <- err
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow token exchange did not start")
	}

	cachedDone := make(chan error, 1)
	go func() {
		token, err := cache.Token(context.Background(), sourcecdk.NewConfig(map[string]string{
			"token_url":     server.URL + "/cached",
			"client_id":     "cached-client",
			"client_secret": "cached-secret",
		}), true)
		if err != nil {
			cachedDone <- err
			return
		}
		if token != "cached-token" {
			cachedDone <- errUnexpectedToken(token)
			return
		}
		cachedDone <- nil
	}()

	select {
	case err := <-cachedDone:
		if err != nil {
			t.Fatalf("cached Token() error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cached Token() blocked behind unrelated token exchange")
	}

	releaseSlowOnce.Do(func() { close(releaseSlow) })
	if err := <-slowDone; err != nil {
		t.Fatalf("slow Token() error = %v", err)
	}
}

type errUnexpectedToken string

func (e errUnexpectedToken) Error() string { return "token = " + string(e) + ", want cached-token" }
