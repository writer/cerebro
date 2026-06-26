package userpreferences

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubStore struct {
	records map[string]*ports.UserPreferences
}

func newStubStore() *stubStore {
	return &stubStore{records: map[string]*ports.UserPreferences{}}
}

func (s *stubStore) Ping(context.Context) error { return nil }

func (s *stubStore) PutUserPreferences(_ context.Context, preferences *ports.UserPreferences) error {
	copied := *preferences
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = time.Now().UTC()
	}
	copied.UpdatedAt = time.Now().UTC()
	s.records[stubKey(copied.TenantID, copied.UserID)] = &copied
	return nil
}

func (s *stubStore) GetUserPreferences(_ context.Context, key ports.UserPreferenceKey) (*ports.UserPreferences, error) {
	record, ok := s.records[stubKey(key.TenantID, key.UserID)]
	if !ok {
		return nil, ports.ErrUserPreferencesNotFound
	}
	copied := *record
	return &copied, nil
}

func stubKey(tenantID string, userID string) string {
	return tenantID + "\x00" + userID
}

func testHandler(store ports.StateStore) Handler {
	return NewHandler(store, func(context.Context, string) (string, error) {
		return "local", nil
	})
}

func testRequest(method, body string) *http.Request {
	request := httptest.NewRequest(method, "/user/preferences", strings.NewReader(body))
	request.Header.Set("X-Cerebro-User-ID", "person@example.com")
	return request
}

func TestPutPersistsForResolvedUser(t *testing.T) {
	store := newStubStore()
	handler := testHandler(store)

	recorder := httptest.NewRecorder()
	body := `{"preferences":{"homepage":{"sections":{"trends":false}},"display":{"density":"compact"}}}`
	handler.Put(recorder, testRequest(http.MethodPut, body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response responseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.TenantID != "local" || response.UserID != "person@example.com" || !response.Persisted {
		t.Fatalf("unexpected response %+v", response)
	}
	var preferences map[string]any
	if err := json.Unmarshal(response.Preferences, &preferences); err != nil {
		t.Fatalf("decode preferences: %v", err)
	}
	homepage := preferences["homepage"].(map[string]any)
	sections := homepage["sections"].(map[string]any)
	if sections["trends"] != false {
		t.Fatalf("preferences JSON = %s", response.Preferences)
	}
}

func TestGetReturnsDefaultWhenMissing(t *testing.T) {
	handler := testHandler(newStubStore())

	recorder := httptest.NewRecorder()
	handler.Get(recorder, testRequest(http.MethodGet, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response responseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Persisted || string(response.Preferences) != "{}" {
		t.Fatalf("missing preferences response = %+v", response)
	}
}

func TestPutRejectsNonObjectPayload(t *testing.T) {
	handler := testHandler(newStubStore())

	recorder := httptest.NewRecorder()
	handler.Put(recorder, testRequest(http.MethodPut, `{"preferences":[]}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestKeyFallsBackToAnonymousUser(t *testing.T) {
	handler := testHandler(newStubStore())
	key, err := handler.keyForRequest(httptest.NewRequest(http.MethodGet, "/user/preferences", nil), "")
	if err != nil {
		t.Fatalf("keyForRequest() error = %v", err)
	}
	if key.TenantID != "local" || key.UserID != "anonymous" {
		t.Fatalf("key = %+v, want local/anonymous", key)
	}
}

func TestTenantResolverErrorRejectsRequest(t *testing.T) {
	handler := NewHandler(newStubStore(), func(context.Context, string) (string, error) {
		return "", errors.New("tenant rejected")
	})
	recorder := httptest.NewRecorder()
	handler.Get(recorder, testRequest(http.MethodGet, ""))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}
