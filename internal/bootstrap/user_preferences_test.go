package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type stubUserPreferenceStore struct {
	records map[string]*ports.UserPreferences
}

func newStubUserPreferenceStore() *stubUserPreferenceStore {
	return &stubUserPreferenceStore{records: map[string]*ports.UserPreferences{}}
}

func (s *stubUserPreferenceStore) Ping(context.Context) error { return nil }

func (s *stubUserPreferenceStore) PutUserPreferences(_ context.Context, preferences *ports.UserPreferences) error {
	copied := *preferences
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = time.Now().UTC()
	}
	copied.UpdatedAt = time.Now().UTC()
	s.records[userPreferenceStubKey(copied.TenantID, copied.UserID)] = &copied
	return nil
}

func (s *stubUserPreferenceStore) GetUserPreferences(_ context.Context, key ports.UserPreferenceKey) (*ports.UserPreferences, error) {
	record, ok := s.records[userPreferenceStubKey(key.TenantID, key.UserID)]
	if !ok {
		return nil, ports.ErrUserPreferencesNotFound
	}
	copied := *record
	return &copied, nil
}

func userPreferenceStubKey(tenantID string, userID string) string {
	return tenantID + "\x00" + userID
}

func userPreferenceTestApp(store ports.StateStore) *App {
	return New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
}

func userPreferenceTestRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("X-Cerebro-User-ID", "person@example.com")
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "local"},
	}))
}

func TestHandlePutUserPreferencesPersistsForResolvedUser(t *testing.T) {
	store := newStubUserPreferenceStore()
	app := userPreferenceTestApp(store)

	recorder := httptest.NewRecorder()
	body := `{"preferences":{"homepage":{"sections":{"trends":false}},"display":{"density":"compact"}}}`
	app.handlePutUserPreferences(recorder, userPreferenceTestRequest(http.MethodPut, "/user/preferences", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response userPreferencesResponse
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

func TestHandleGetUserPreferencesReturnsDefaultWhenMissing(t *testing.T) {
	app := userPreferenceTestApp(newStubUserPreferenceStore())

	recorder := httptest.NewRecorder()
	app.handleGetUserPreferences(recorder, userPreferenceTestRequest(http.MethodGet, "/user/preferences", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response userPreferencesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Persisted || string(response.Preferences) != "{}" {
		t.Fatalf("missing preferences response = %+v", response)
	}
}

func TestHandlePutUserPreferencesRejectsNonObjectPayload(t *testing.T) {
	app := userPreferenceTestApp(newStubUserPreferenceStore())

	recorder := httptest.NewRecorder()
	app.handlePutUserPreferences(recorder, userPreferenceTestRequest(http.MethodPut, "/user/preferences", `{"preferences":[]}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestUserPreferenceKeyFallsBackToAuthPrincipal(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/user/preferences", nil)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{Name: "api-user", TenantID: "writer"},
	}))
	key, err := userPreferenceKeyForRequest(request, "")
	if err != nil {
		t.Fatalf("userPreferenceKeyForRequest() error = %v", err)
	}
	if key.TenantID != "writer" || key.UserID != "api-user" {
		t.Fatalf("key = %+v, want writer/api-user", key)
	}
}
