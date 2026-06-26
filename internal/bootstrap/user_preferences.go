package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const userPreferencesMaxBytes = 64 * 1024

var errUserPreferencesUnavailable = errors.New("user preferences are not configured")

var userPreferenceErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(errUserPreferencesUnavailable), httpStatus: http.StatusServiceUnavailable},
	{match: matchesAnyError(errInvalidHTTPRequest), httpStatus: http.StatusBadRequest},
}

type userPreferencesRequest struct {
	TenantID    string          `json:"tenant_id"`
	Preferences json.RawMessage `json:"preferences"`
}

type userPreferencesResponse struct {
	TenantID    string          `json:"tenant_id"`
	UserID      string          `json:"user_id"`
	Preferences json.RawMessage `json:"preferences"`
	Persisted   bool            `json:"persisted"`
	CreatedAt   string          `json:"created_at,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
}

func (a *App) handleGetUserPreferences(w http.ResponseWriter, r *http.Request) {
	store := userPreferenceStore(a.deps.StateStore)
	if store == nil {
		writeUserPreferenceError(w, errUserPreferencesUnavailable)
		return
	}
	key, err := userPreferenceKeyForRequest(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeUserPreferenceError(w, err)
		return
	}
	preferences, err := store.GetUserPreferences(r.Context(), key)
	if err != nil {
		if errors.Is(err, ports.ErrUserPreferencesNotFound) {
			writeJSON(w, http.StatusOK, userPreferenceResponseFor(key.TenantID, key.UserID, []byte("{}"), false, time.Time{}, time.Time{}))
			return
		}
		writeUserPreferenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userPreferenceResponseFor(preferences.TenantID, preferences.UserID, []byte(preferences.PreferencesJSON), true, preferences.CreatedAt, preferences.UpdatedAt))
}

func (a *App) handlePutUserPreferences(w http.ResponseWriter, r *http.Request) {
	store := userPreferenceStore(a.deps.StateStore)
	if store == nil {
		writeUserPreferenceError(w, errUserPreferencesUnavailable)
		return
	}
	var request userPreferencesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, userPreferencesMaxBytes)).Decode(&request); err != nil {
		writeUserPreferenceError(w, fmt.Errorf("%w: decode user preferences: %w", errInvalidHTTPRequest, err))
		return
	}
	key, err := userPreferenceKeyForRequest(r, request.TenantID)
	if err != nil {
		writeUserPreferenceError(w, err)
		return
	}
	payload := bytesTrimSpace(request.Preferences)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if len(payload) > userPreferencesMaxBytes {
		writeUserPreferenceError(w, fmt.Errorf("%w: preferences must be at most %d bytes", errInvalidHTTPRequest, userPreferencesMaxBytes))
		return
	}
	if !json.Valid(payload) || !validUserPreferencePayload(payload) {
		writeUserPreferenceError(w, fmt.Errorf("%w: preferences must be a JSON object", errInvalidHTTPRequest))
		return
	}
	record := &ports.UserPreferences{
		TenantID:        key.TenantID,
		UserID:          key.UserID,
		PreferencesJSON: string(payload),
	}
	if err := store.PutUserPreferences(r.Context(), record); err != nil {
		writeUserPreferenceError(w, err)
		return
	}
	stored, err := store.GetUserPreferences(r.Context(), key)
	if err != nil {
		writeUserPreferenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userPreferenceResponseFor(stored.TenantID, stored.UserID, []byte(stored.PreferencesJSON), true, stored.CreatedAt, stored.UpdatedAt))
}

func userPreferenceKeyForRequest(r *http.Request, requestedTenantID string) (ports.UserPreferenceKey, error) {
	tenantID, err := effectiveTenantFilter(r.Context(), requestedTenantID)
	if err != nil {
		return ports.UserPreferenceKey{}, err
	}
	if tenantID == "" {
		tenantID = "default"
	}
	userID := userPreferenceUserID(r)
	if userID == "" {
		return ports.UserPreferenceKey{}, fmt.Errorf("%w: user_id is required", errInvalidHTTPRequest)
	}
	return ports.UserPreferenceKey{TenantID: tenantID, UserID: userID}, nil
}

func userPreferenceUserID(r *http.Request) string {
	if r != nil {
		for _, header := range []string{"X-Cerebro-User-ID", "X-Cerebro-User-Email", "X-Cerebro-User-Subject", "X-Cerebro-User-Name"} {
			if value := cleanUserPreferenceID(r.Header.Get(header)); value != "" {
				return value
			}
		}
	}
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		for _, value := range []string{auth.principal.Name, auth.principal.ClientID, auth.principal.DeviceID, auth.principal.CredentialID} {
			if cleaned := cleanUserPreferenceID(value); cleaned != "" {
				return cleaned
			}
		}
	}
	return "anonymous"
}

func cleanUserPreferenceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > 240 {
		value = value[:240]
	}
	return strings.TrimSpace(value)
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}

func validUserPreferencePayload(payload []byte) bool {
	var decoded map[string]any
	return json.Unmarshal(payload, &decoded) == nil
}

func userPreferenceResponseFor(tenantID string, userID string, preferences []byte, persisted bool, createdAt time.Time, updatedAt time.Time) userPreferencesResponse {
	if len(preferences) == 0 || !json.Valid(preferences) {
		preferences = []byte("{}")
	}
	response := userPreferencesResponse{
		TenantID:    strings.TrimSpace(tenantID),
		UserID:      strings.TrimSpace(userID),
		Preferences: json.RawMessage(preferences),
		Persisted:   persisted,
	}
	if !createdAt.IsZero() {
		response.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	}
	if !updatedAt.IsZero() {
		response.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	}
	return response
}

func userPreferenceStore(store ports.StateStore) ports.UserPreferenceStore {
	preferenceStore, _ := store.(ports.UserPreferenceStore)
	return preferenceStore
}

func writeUserPreferenceError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, userPreferenceErrorMappings)
}
