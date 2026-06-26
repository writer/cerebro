package userpreferences

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

const maxPreferenceBytes = 64 * 1024
const maxUserIDBytes = 240

var errUserIdentityUnavailable = errors.New("authenticated user identity is required")

// TenantResolver returns the effective tenant for a request body or query value.
type TenantResolver func(context.Context, string) (string, error)

// UserResolver returns the authenticated user identity from trusted request context.
type UserResolver func(context.Context) string

// Handler serves user-level console preferences.
type Handler struct {
	store          ports.UserPreferenceStore
	tenantResolver TenantResolver
	userResolver   UserResolver
}

type requestBody struct {
	TenantID    string           `json:"tenant_id"`
	Preferences *json.RawMessage `json:"preferences"`
}

type responseBody struct {
	TenantID    string          `json:"tenant_id"`
	UserID      string          `json:"user_id"`
	Preferences json.RawMessage `json:"preferences"`
	Persisted   bool            `json:"persisted"`
	CreatedAt   string          `json:"created_at,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
}

// NewHandler builds a preferences handler from the optional StateStore
// capability. A missing capability returns 503 from request handlers.
func NewHandler(store ports.StateStore, tenantResolver TenantResolver, userResolver UserResolver) Handler {
	preferenceStore, _ := store.(ports.UserPreferenceStore)
	if isNil(preferenceStore) {
		preferenceStore = nil
	}
	return Handler{store: preferenceStore, tenantResolver: tenantResolver, userResolver: userResolver}
}

// Get returns persisted preferences, or defaults when the user has not saved any.
func (h Handler) Get(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "user preferences are not configured")
		return
	}
	key, err := h.keyForRequest(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, statusForKeyError(err), err.Error())
		return
	}
	preferences, err := h.store.GetUserPreferences(r.Context(), key)
	if err != nil {
		if errors.Is(err, ports.ErrUserPreferencesNotFound) {
			writeJSON(w, http.StatusOK, responseFor(key.TenantID, key.UserID, []byte("{}"), false, time.Time{}, time.Time{}))
			return
		}
		writeError(w, http.StatusInternalServerError, "user preferences unavailable")
		return
	}
	writeJSON(w, http.StatusOK, responseFor(preferences.TenantID, preferences.UserID, []byte(preferences.PreferencesJSON), true, preferences.CreatedAt, preferences.UpdatedAt))
}

// Put validates and stores preferences for the resolved tenant/user pair.
func (h Handler) Put(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "user preferences are not configured")
		return
	}
	var request requestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPreferenceBytes)).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid user preferences request")
		return
	}
	key, err := h.keyForRequest(r, request.TenantID)
	if err != nil {
		writeError(w, statusForKeyError(err), err.Error())
		return
	}
	if request.Preferences == nil {
		writeError(w, http.StatusBadRequest, "preferences are required")
		return
	}
	payload := bytes.TrimSpace(*request.Preferences)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if len(payload) > maxPreferenceBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("preferences must be at most %d bytes", maxPreferenceBytes))
		return
	}
	if !json.Valid(payload) || !validPreferencePayload(payload) {
		writeError(w, http.StatusBadRequest, "preferences must be a JSON object")
		return
	}
	record := &ports.UserPreferences{
		TenantID:        key.TenantID,
		UserID:          key.UserID,
		PreferencesJSON: string(payload),
	}
	if err := h.store.PutUserPreferences(r.Context(), record); err != nil {
		writeError(w, http.StatusInternalServerError, "user preferences unavailable")
		return
	}
	stored, err := h.store.GetUserPreferences(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user preferences unavailable")
		return
	}
	writeJSON(w, http.StatusOK, responseFor(stored.TenantID, stored.UserID, []byte(stored.PreferencesJSON), true, stored.CreatedAt, stored.UpdatedAt))
}

func (h Handler) keyForRequest(r *http.Request, requestedTenantID string) (ports.UserPreferenceKey, error) {
	if r == nil {
		tenantID := strings.TrimSpace(requestedTenantID)
		if tenantID == "" {
			tenantID = "default"
		}
		return ports.UserPreferenceKey{TenantID: tenantID, UserID: "anonymous"}, nil
	}
	ctx := r.Context()
	tenantID := strings.TrimSpace(requestedTenantID)
	if h.tenantResolver != nil {
		resolvedTenantID, err := h.tenantResolver(ctx, requestedTenantID)
		if err != nil {
			return ports.UserPreferenceKey{}, err
		}
		tenantID = strings.TrimSpace(resolvedTenantID)
	}
	if tenantID == "" {
		tenantID = "default"
	}
	userID, err := h.userIDForContext(ctx)
	if err != nil {
		return ports.UserPreferenceKey{}, err
	}
	return ports.UserPreferenceKey{TenantID: tenantID, UserID: userID}, nil
}

func (h Handler) userIDForContext(ctx context.Context) (string, error) {
	if h.userResolver != nil {
		if value := cleanUserID(h.userResolver(ctx)); value != "" {
			return value, nil
		}
		return "", errUserIdentityUnavailable
	}
	return "anonymous", nil
}

func cleanUserID(value string) string {
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
	if len(value) > maxUserIDBytes {
		value = truncateValidUTF8(value, maxUserIDBytes)
	}
	return strings.TrimSpace(value)
}

func truncateValidUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for end := limit; end > 0; end-- {
		if utf8.ValidString(value[:end]) {
			return value[:end]
		}
	}
	return ""
}

func validPreferencePayload(payload []byte) bool {
	var decoded map[string]any
	return json.Unmarshal(payload, &decoded) == nil && decoded != nil
}

func responseFor(tenantID string, userID string, preferences []byte, persisted bool, createdAt time.Time, updatedAt time.Time) responseBody {
	if len(preferences) == 0 || !json.Valid(preferences) {
		preferences = []byte("{}")
	}
	response := responseBody{
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

func statusForKeyError(error) int {
	return http.StatusForbidden
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	http.Error(w, message, statusCode)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.TypeOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}
